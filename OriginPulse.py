import requests
import os
import re
import pandas as pd
import time
from akamai.edgegrid import EdgeGridAuth, EdgeRc
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# --- CLEAR TERMINAL WATERMARK ---
print("\n" + "="*75)
print("🎯 INVENTORY ENGINE: CUSTOM TRUST + SANITIZED CRYPTO DEEP PARSER")
print("="*75 + "\n")

# --- CONFIGURATION ---
edgerc_path = os.path.expanduser("~/.edgerc")
edgerc = EdgeRc(edgerc_path)
section = 'papi' 

SWITCH_KEY = "xxx"
CONTRACT_ID = "ctr_xxx"

baseurl = edgerc.get(section, 'host')
s = requests.Session()
s.auth = EdgeGridAuth(
    client_token=edgerc.get(section, 'client_token'),
    client_secret=edgerc.get(section, 'client_secret'),
    access_token=edgerc.get(section, 'access_token')
)

def get_network_versions(p_id, base_params):
    act_url = f"https://{baseurl}/papi/v1/properties/{p_id}/activations"
    res = s.get(act_url, params=base_params)
    staging_v, prod_v = "None", "None"
    
    if res.status_code == 200:
        activations = res.json().get('activations', {}).get('items', [])
        found_staging = False
        found_production = False
        
        for act in activations:
            network = act.get('network')
            status = act.get('status')
            act_type = act.get('activationType', 'ACTIVATE')
            
            if network == 'STAGING' and not found_staging:
                if status == 'ACTIVE':
                    staging_v = "None" if act_type == 'DEACTIVATE' else str(act.get('propertyVersion'))
                    found_staging = True
            elif network == 'PRODUCTION' and not found_production:
                if status == 'ACTIVE':
                    prod_v = "None" if act_type == 'DEACTIVATE' else str(act.get('propertyVersion'))
                    found_production = True
                    
            if found_staging and found_production:
                break
    return staging_v, prod_v

def inspect_rules_recursively(rule_node, current_rule_name="Default Rule", origin_behaviors=None):
    if origin_behaviors is None:
        origin_behaviors = []
    rule_name = rule_node.get('name', current_rule_name)
    for behavior in rule_node.get('behaviors', []):
        if behavior.get('name') == 'origin':
            behavior['found_in_rule'] = rule_name
            origin_behaviors.append(behavior)
    for child in rule_node.get('children', []):
        inspect_rules_recursively(child, rule_name, origin_behaviors)
    return origin_behaviors

def parse_and_analyze_entries(raw_cert_list):
    """
    Parses elements dynamically. Strips out JSON backslash escape strings (Byte 92),
    standardizes multi-line PEM format strings, and reads binary certificate tags cleanly.
    """
    cert_diagnostics = []
    for idx, raw_entry in enumerate(raw_cert_list, 1):
        if not raw_entry:
            continue
        
        # Convert to string and clear any double-escaped literal "\n" into real spaces or newlines
        clean_entry = str(raw_entry).replace("\\n", "\n").replace("\\r", "").strip()
        
        if "BEGIN CERTIFICATE" in clean_entry.upper():
            try:
                # Isolate the exact content block between standard boundaries
                match = re.search(r'-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----', clean_entry, re.DOTALL | re.IGNORECASE)
                if match:
                    # Clean out literal backslashes '\' (Byte 92) that leak from JSON serialization layers
                    sanitized_body = match.group(1).replace("\\", "").strip()
                else:
                    sanitized_body = clean_entry.replace("-----BEGIN CERTIFICATE-----", "").replace("-----END CERTIFICATE-----", "").replace("\\", "").strip()
                
                # Rebuild standard, structural multi-line PEM file
                pem_body = f"-----BEGIN CERTIFICATE-----\n{sanitized_body}\n-----END CERTIFICATE-----"
                
                # Ingest safely into the cryptography binary loader
                cert = x509.load_pem_x509_certificate(pem_body.encode('utf-8'), default_backend())
                
                common_name = "Unknown CN"
                for attr in cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME):
                    common_name = attr.value
                    
                try:
                    expiry_date = cert.not_valid_after_utc
                except AttributeError:
                    expiry_date = cert.not_valid_after
                expiry_str = expiry_date.strftime("%Y-%m-%d")
                
                is_self_signed = (cert.subject == cert.issuer)
                is_ca = False
                try:
                    is_ca = cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
                except Exception:
                    pass
                    
                cert_type = "Root" if is_self_signed else ("Intermediate" if is_ca else "Leaf")
                cert_diagnostics.append(f"[Cert #{idx} ({cert_type}): CN={common_name}, Expire={expiry_str}]")
            except Exception as e:
                cert_diagnostics.append(f"[Cert #{idx} (Raw Text): Formatting Error ({str(e)})]")
        else:
            # Handles instances where Akamai provides a simple Cert ID string sequence instead of plain text
            cert_diagnostics.append(f"[CA ID #{idx} (System Reference ID): {clean_entry}]")
            
    return cert_diagnostics

def run_targeted_inventory():
    base_params = {'accountSwitchKey': SWITCH_KEY}
    groups_data = s.get(f"https://{baseurl}/papi/v1/groups", params=base_params).json()['groups']['items']
    filtered_records = []

    for group in groups_data:
        g_id = group['groupId']
        g_name = group.get('groupName', g_id)
        
        props_res = s.get(f"https://{baseurl}/papi/v1/properties", params={'accountSwitchKey': SWITCH_KEY, 'contractId': CONTRACT_ID, 'groupId': g_id})
        if props_res.status_code != 200:
            continue
            
        for prop in props_res.json()['properties']['items']:
            p_name = prop['propertyName']
            p_id = prop['propertyId']
            v_id = prop['latestVersion']
            c_id = prop['contractId']

            print(f"   🔍 Inspecting Rules Payload: {p_name}")
            
            rules_res = s.get(f"https://{baseurl}/papi/v1/properties/{p_id}/versions/{v_id}/rules", params={'accountSwitchKey': SWITCH_KEY, 'contractId': c_id, 'groupId': g_id})
            if rules_res.status_code != 200:
                continue
                
            all_origins = inspect_rules_recursively(rules_res.json().get('rules', {}))
            is_valid_custom_with_data = False
            rule_descriptions = []
            
            for origin in all_origins:
                options = origin.get('options', {})
                certs_to_honor = options.get('originCertsToHonor')
                mode = options.get('verificationMode')
                rule_where_found = origin.get('found_in_rule', 'Unknown Rule')
                
                if certs_to_honor == "COMBO" or mode == "CUSTOM":
                    custom_certs = options.get('customCertificateAuthorities', [])
                    custom_certs_alt = options.get('customCertificates', [])
                    combined_entries = custom_certs + custom_certs_alt
                    filled_entries = [c for c in combined_entries if str(c).strip()]
                    
                    if len(filled_entries) > 0:
                        is_valid_custom_with_data = True
                        parsed_details = parse_and_analyze_entries(filled_entries)
                        detail_string = " | ".join(parsed_details)
                        rule_descriptions.append(f"Rule '{rule_where_found}': Trust: Custom - {detail_string}")

            if is_valid_custom_with_data:
                staging_v, prod_v = get_network_versions(p_id, base_params)
                filtered_records.append({
                    "Group Name": g_name,
                    "Property Name": p_name,
                    "Production Version": prod_v,
                    "Staging Version": staging_v,
                    "Audit Status": "No Action Needed",
                    "Configuration Comments / Analysis": " | ".join(rule_descriptions)
                })
            
        time.sleep(0.02)

    if filtered_records:
        df = pd.DataFrame(filtered_records)
        df = df[["Group Name", "Property Name", "Production Version", "Staging Version", "Audit Status", "Configuration Comments / Analysis"]]
        
        output_filename = "Akamai_Custom_Uploaded_Inventory.xlsx"
        df.to_excel(output_filename, index=False)
        print(f"\n🎉 SUCCESS: Inventory compiled! {len(filtered_records)} properties written to '{output_filename}'")
    else:
        print("\n⚠️ COMPLETE: No properties matched the Custom Trust + Uploaded data criteria.")

if __name__ == "__main__":
    run_targeted_inventory()