import base64
import hashlib
import re
import requests
from akamai.edgegrid import EdgeGridAuth

# -------------------------------------------------------------
# 1. AUTHENTICATION & CLIENT INITIALIZATION
# -------------------------------------------------------------
session = requests.Session()

# Host gateway connection point
AKAMAI_HOST = "xxxx"

session.auth = EdgeGridAuth(
    client_token="xxx",
    client_secret="xxxx",
    access_token="xxxx"
)

# -------------------------------------------------------------
# 2. TARGET CONFIGURATION DEFINITIONS
# -------------------------------------------------------------
# Define the collection of property targets to scan and modify globally
TARGET_PROPERTY_NAMES = [
       "nonprod.synchronyincubation.com",
       "Ecarts_Non-Prod"
]

SWITCH_KEY = "xxxx"
CHANGE_MANAGEMENT_NOTE = "SYF-794 | Bulk updated to upload certificates in origin behavior"

# -------------------------------------------------------------
# 3. REARRANGED MULTI-CERTIFICATE DATA LIBRARY
# -------------------------------------------------------------
CERTIFICATE_LIBRARY = [
    {
        "subjectCN": "Synchrony Issuing CA",
        "notBefore": 1807366835000,
        "notAfter": 1807453235000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Synchrony Issuing CA - G4",
        "notBefore": 1726501068000,
        "notAfter": 2042033868000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Synchrony Issuing CA - G2",
        "notBefore": 1726501281000,
        "notAfter": 2042034081000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Internal Hostnames Root CA 1",
        "notBefore": 1454690793000,
        "notAfter": 2085842793000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Synchrony Root CA - G4",
        "notBefore": 1726501002000,
        "notAfter": 2515419402000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----

-----END CERTIFICATE-----"""
    }
]

# -------------------------------------------------------------
# 4. CRYPTOGRAPHIC UTILITIES & PAYLOAD GENERATION
# -------------------------------------------------------------
def calculate_sha1_fingerprint(pem_str):
    lines = pem_str.splitlines()
    base64_lines = [line for line in lines if not line.strip().startswith("-----")]
    combined_body = "".join(base64_lines)
    clean_body = "".join(re.findall(r'[A-Za-z0-9+/]', combined_body))
    
    if len(clean_body) % 4 == 1:
        clean_body = clean_body[:-1]
        
    missing_padding = len(clean_body) % 4
    if missing_padding:
        clean_body += '=' * (4 - missing_padding)
        
    der_bytes = base64.b64decode(clean_body)
    return hashlib.sha1(der_bytes).hexdigest().lower()

NEW_CERT_OBJECTS = []
print("[PRE-FLIGHT] Ingesting and formatting structured certificate library...")

for cert_entry in CERTIFICATE_LIBRARY:
    pem_block = cert_entry["pemEncodedCert"]
    fingerprint = calculate_sha1_fingerprint(pem_block)
    
    NEW_CERT_OBJECTS.append({
        "pemEncodedCert": pem_block.strip(),
        "sha1Fingerprint": fingerprint,
        "subjectCN": cert_entry["subjectCN"],
        "notBefore": cert_entry["notBefore"],
        "notAfter": cert_entry["notAfter"]
    })
    print(f"  -> Curated UI Object: '{cert_entry['subjectCN']}' | SHA-1: {fingerprint}")

# -------------------------------------------------------------
# 5. MULTI-CERT EVALUATION & TRANSFORMATION ENGINE
# -------------------------------------------------------------
def evaluate_origin_behavior(behavior, apply_updates=False):
    options = behavior.get("options", {})
    origin_type = options.get("originType")
    hostname = options.get("hostname", "Unknown Hostname")
    
    if origin_type == "NET_STORAGE":
        return False, f"[SKIP] {hostname} is a NetStorage origin."
        
    if origin_type == "CUSTOMER":
        changed = False
        logs = []
        
        if options.get("verificationMode") != "CUSTOM":
            if apply_updates:
                options["verificationMode"] = "CUSTOM"
            changed = True
            logs.append("Flip verificationMode to CUSTOM")
            
        if options.get("originCertsToHonor") != "COMBO":
            if apply_updates:
                options["originCertsToHonor"] = "COMBO"
            changed = True
            logs.append("Set originCertsToHonor to COMBO")
            
        std_cas = options.get("standardCertificateAuthorities", [])
        if not isinstance(std_cas, list):
            std_cas = []
            
        if "akamai-permissive" not in std_cas:
            if apply_updates:
                std_cas.append("akamai-permissive")
            changed = True
            
        if "THIRD_PARTY_AMAZON" not in std_cas:
            if apply_updates:
                std_cas.append("THIRD_PARTY_AMAZON")
            changed = True
            logs.append("Enable 'Third Party Certificate Store' (Added THIRD_PARTY_AMAZON)")
            
        if changed and apply_updates:
            options["standardCertificateAuthorities"] = std_cas
            
        custom_ca = options.get("customCertificateAuthorities", [])
        if not isinstance(custom_ca, list):
            custom_ca = []
            
        existing_fingerprints = {
            str(c.get("sha1Fingerprint", "")).replace(":", "").lower()
            for c in custom_ca if isinstance(c, dict)
        }
        
        for cert_obj in NEW_CERT_OBJECTS:
            target_sha1 = cert_obj["sha1Fingerprint"]
            
            if target_sha1 not in existing_fingerprints:
                if apply_updates:
                    custom_ca.append(cert_obj)
                changed = True
                logs.append(f"Uploaded certificate [{cert_obj['subjectCN']}]")
            else:
                logs.append(f"Certificate [{cert_obj['subjectCN']}] already verified")
                
        if changed and apply_updates:
            options["customCertificateAuthorities"] = custom_ca
            behavior["options"] = options
            
        if changed:
            return True, f"[ACTION REQUIRED] {hostname}: " + " | ".join(logs)
        else:
            return False, f"[SKIP] {hostname}: Already matches expected multi-cert layout."

    return False, f"[SKIP] Unhandled configuration footprint on {hostname}."

# -------------------------------------------------------------
# 6. RECURSIVE TREE TRAVERSAL
# -------------------------------------------------------------
def walk_rules_tree(rule_node, apply_updates=False):
    tree_changed = False
    
    if "behaviors" in rule_node:
        for i, behavior in enumerate(rule_node["behaviors"]):
            if behavior.get("name") == "origin":
                changed, msg = evaluate_origin_behavior(behavior, apply_updates)
                if changed:
                    tree_changed = True
                    if not apply_updates:
                        print(f"    {msg}")
                    else:
                        rule_node["behaviors"][i] = behavior
                        
    if "children" in rule_node:
        for child in rule_node["children"]:
            if walk_rules_tree(child, apply_updates):
                tree_changed = True
                
    return tree_changed

# -------------------------------------------------------------
# 7. ISOLATED PROPERTY EXECUTION PROCESSING LOGIC
# -------------------------------------------------------------
def process_property(property_item, context_params):
    prop_name = property_item["propertyName"]
    prop_id = property_item["propertyId"]
    
    print(f"\n⚡ [START] Executing Logic Core on Target Property: '{prop_name}' (ID: {prop_id})")
    
    versions_endpoint = f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions"
    versions_res = session.get(versions_endpoint, params=context_params)
    
    if versions_res.status_code != 200:
        print(f"  [ERROR] Failed to query production context options. Status: {versions_res.status_code}")
        return False

    versions_list = versions_res.json().get("versions", {}).get("items", [])
    prod_version = next((v for v in versions_list if v.get("productionStatus") == "ACTIVE"), None)
    
    if not prod_version:
        print(f"  [SKIP] Could not detect an ACTIVE Production anchor context version layer.")
        return False
        
    prod_v_num = prod_version["propertyVersion"]
    print(f"  [INFO] Isolated production anchor state validation level at v{prod_v_num}.")
    
    # PHASE 1: READ-ONLY PRE-SCAN
    print(f"  [PRE-SCAN] Inspecting active version structure logs...")
    prod_rules_endpoint = f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions/{prod_v_num}/rules"
    prod_rules_payload = session.get(prod_rules_endpoint, params=context_params).json()
    
    changes_required = walk_rules_tree(prod_rules_payload.get("rules", {}), apply_updates=False)
    
    if not changes_required:
        print(f"  [COMPLETE] Configuration payload validation matched criteria. No structural mutations needed.")
        return True

    # PHASE 2: DRAFT STEP VERSION BRANCHING
    print(f"  [EXECUTION] Rules delta identified. Branching development pipeline offset from v{prod_v_num}...")
    create_version_payload = {"createFromVersion": prod_v_num}
    new_v_res = session.post(versions_endpoint, params=context_params, json=create_version_payload).json()
    
    new_v_num = new_v_res.get("versionLink", "").split("?")[0].split("/")[-1] or new_v_res.get("propertyVersion")
    print(f"  [SUCCESS] Configuration workspace created: Editing version branch v{new_v_num}")
    
    draft_rules_endpoint = f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions/{new_v_num}/rules"
    draft_rules_payload = session.get(draft_rules_endpoint, params=context_params).json()
    
    # Transform configuration structures with certificates updates mapping active
    walk_rules_tree(draft_rules_payload.get("rules", {}), apply_updates=True)
    
    # Save the Rule Tree Modifications
    print(f"  [INFO] Pushing updated rule structures into version placeholder v{new_v_num}...")
    save_res = session.put(draft_rules_endpoint, params=context_params, json=draft_rules_payload)
    
    if save_res.status_code in [200, 201]:
        print(f"  [COMPLETE] Successfully synchronized updated certificate sets inside structural layer v{new_v_num}.")
        
        # POPULATE CONTROL CENTER "VERSION NOTES" FIELD
        print(f"  [INFO] Attaching structural identifier to systemic Control Center logs...")
        version_meta_endpoint = f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions/{new_v_num}"
        note_payload = {"description": CHANGE_MANAGEMENT_NOTE}
        
        note_res = session.put(version_meta_endpoint, params=context_params, json=note_payload)
        if note_res.status_code in [200, 201]:
            print(f"  [SUCCESS] Audit logs linked successfully to deployment trace footprint.")
            return True
        else:
            print(f"  [WARN] Data saved safely, but description update request dropped. Status: {note_res.status_code}")
            return True
    else:
        print(f"  [FAIL] Akamai PAPI engine rejected rule injection ruleset update. Status: {save_res.status_code}")
        return False

# -------------------------------------------------------------
# 8. BULK ORCHESTRATION PIPELINE
# -------------------------------------------------------------
def run_bulk_updates():
    if not NEW_CERT_OBJECTS:
        print("[CRITICAL] Structured certificate arrays are empty. Execution stopped.")
        return

    print(f"\n[INFO] Discovering accessible groups and contracts within switch-key context...")
    
    groups_endpoint = f"https://{AKAMAI_HOST}/papi/v1/groups"
    base_discovery_params = {"accountSwitchKey": SWITCH_KEY}
    groups_res = session.get(groups_endpoint, params=base_discovery_params)
    
    if groups_res.status_code != 200:
        print(f"[CRITICAL] Group context exploration failed. Status: {groups_res.status_code}")
        return
        
    group_items = groups_res.json().get("groups", {}).get("items", [])
    processed_properties = set()
    
    # Traverse through all group structures dynamically without breaking loops prematurely
    for group in group_items:
        g_id = group.get("groupId")
        for c_id in group.get("contractIds", []):
            
            # Localized parameters configuration matrix for target querying operations
            iter_params = {
                "accountSwitchKey": SWITCH_KEY, 
                "contractId": c_id, 
                "groupId": g_id
            }
            
            properties_res = session.get(f"https://{AKAMAI_HOST}/papi/v1/properties", params=iter_params)
            if properties_res.status_code == 200:
                property_items = properties_res.json().get("properties", {}).get("items", [])
                
                for prop in property_items:
                    current_prop_name = prop.get("propertyName")
                    
                    # Matches active items inside configuration listing array
                    if current_prop_name in TARGET_PROPERTY_NAMES:
                        process_property(prop, iter_params)
                        processed_properties.add(current_prop_name)
                        
    # End of run diagnostics block
    unprocessed_targets = set(TARGET_PROPERTY_NAMES) - processed_properties
    print("\n" + "="*60)
    print("BULK UPDATE PROCESSING JOB EXECUTION SUMMARY")
    print("="*60)
    print(f"Successfully processed targets: {list(processed_properties)}")
    if unprocessed_targets:
        print(f"Targets missing/not found in current context permissions: {list(unprocessed_targets)}")
    print("="*60 + "\n")

if __name__ == "__main__":
    run_bulk_updates()
