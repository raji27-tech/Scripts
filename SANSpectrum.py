import requests
import os
import pandas as pd
import time
from akamai.edgegrid import EdgeGridAuth, EdgeRc

# --- CLEAR TERMINAL WATERMARK ---
print("\n" + "="*85)
print("🎯 CPS ADVANCED AUDIT ENGINE is running. Sit back and relax until your report is ready! 🎯")
print("🔬 [Real time analysis of edge certificate ]")
print("="*85 + "\n")

# --- CONFIGURATION INITIALIZATION ---
edgerc_path = os.path.expanduser("~/.edgerc")
edgerc = EdgeRc(edgerc_path)
section = 'papi' 

baseurl = edgerc.get(section, 'host')
s = requests.Session()
s.auth = EdgeGridAuth(
    client_token=edgerc.get(section, 'client_token'),
    client_secret=edgerc.get(section, 'client_secret'),
    access_token=edgerc.get(section, 'access_token')
)

def extract_dns_names_safely(deployment_node):
    if not deployment_node:
        return []
    net_config = deployment_node.get('networkConfiguration', {})
    if 'dnsNames' in net_config and isinstance(net_config['dnsNames'], list):
        return [str(name).strip() for name in net_config['dnsNames'] if name]
    dns_settings = net_config.get('dnsNameSettings', {})
    if 'dnsNames' in dns_settings and isinstance(dns_settings['dnsNames'], list):
        return [str(name).strip() for name in dns_settings['dnsNames'] if name]
    sni_settings = net_config.get('sni', {})
    if isinstance(sni_settings, dict) and 'dnsNames' in sni_settings and isinstance(sni_settings['dnsNames'], list):
        return [str(name).strip() for name in sni_settings['dnsNames'] if name]
    return []

def extract_expiry_date(deployment_node):
    if not deployment_node:
        return "Not Deployed"
        
    certs_list = deployment_node.get('certificates', [])
    if isinstance(certs_list, list) and len(certs_list) > 0:
        expiries = []
        for cert in certs_list:
            expiry_raw = cert.get('expiry')
            if expiry_raw:
                clean_date = str(expiry_raw).split('T')[0]
                algo = cert.get('keyAlgorithm', 'Unknown')
                expiries.append(f"{algo}: {clean_date}")
        if expiries:
            return " | ".join(expiries)
            
    primary = deployment_node.get('primaryCertificate', {})
    if primary and primary.get('expiry'):
        return str(primary.get('expiry')).split('T')[0]
        
    return "Unknown"

def run_interactive_audit():
    # --- INTERACTIVE USER INPUT SEGMENTS ---
    switch_key = input("🔑 Please enter the Akamai Switch Key: ").strip()
    if not switch_key:
        print("❌ ERROR: Switch Key cannot be blank. Terminating execution.")
        return

    enrollment_id = input("🆔 Please enter the CPS Enrollment ID: ").strip()
    if not enrollment_id:
        print("❌ ERROR: Enrollment ID cannot be blank. Terminating execution.")
        return

    print("\n" + "~"*65)
    print("⏳ Establishing secure connection and streaming API tokens...")
    print("~"*65 + "\n")

    # Base Target Endpoint Formats
    enrollment_url = f"https://{baseurl}/cps/v2/enrollments/{enrollment_id}"
    deployments_url = f"https://{baseurl}/cps/v2/enrollments/{enrollment_id}/deployments"
    
    params = {'accountSwitchKey': switch_key}
    
    # --- TASK 1: FETCH ENROLLMENT METADATA ---
    print(f"🛰️  [1/2] Extracting Profile Configurations for ID: {enrollment_id}...")
    enr_res = s.get(
        enrollment_url, 
        params=params, 
        headers={'Accept': 'application/vnd.akamai.cps.enrollment.v11+json'}
    )
    
    if enr_res.status_code != 200:
        print(f"❌ Profile Fetch Failed: {enr_res.status_code} - {enr_res.text}")
        return
    enr_data = enr_res.json()

    # Parse core metrics out of structural rules configuration payload
    cert_name = enr_data.get('csr', {}).get('cn', 'Unknown Common Name')
    cert_type = str(enr_data.get('certificateType', 'Unknown')).upper()
    
    # Process Assigned Slots Maps
    p_slots = enr_data.get('productionSlots', []) or []
    s_slots = enr_data.get('stagingSlots', []) or []
    a_slots = enr_data.get('assignedSlots', []) or []
    unique_slots = sorted(list(set([str(slot) for slot in (p_slots + s_slots + a_slots) if slot])))
    slot_number_str = ", ".join(unique_slots) if unique_slots else "None Assigned"

    # Analyze SNI Configuration Flag State
    net_config = enr_data.get('networkConfiguration', {})
    sni_flag = "Unknown"
    if 'sniOnly' in net_config:
        sni_flag = "On" if net_config.get('sniOnly') is True else "Off"
    elif 'sni' in net_config and isinstance(net_config['sni'], dict):
        sni_val = net_config['sni'].get('sniOnly')
        if sni_val is not None:
            sni_flag = "On" if sni_val is True else "Off"

    # Evaluate Staging Change Management Guardrails
    change_management_flag = enr_data.get('changeManagement')
    always_test_on_staging = "Yes" if change_management_flag is True else "No"

    # --- TASK 2: FETCH NETWORK DEPLOYMENTS ---
    print(f"🛰️  [2/2] Scanning Active Network Placements & SAN Sets...")
    dep_res = s.get(
        deployments_url, 
        params=params, 
        headers={'Accept': 'application/vnd.akamai.cps.deployments.v7+json'}
    )
    
    if dep_res.status_code != 200:
        print(f"❌ Deployments Fetch Failed: {dep_res.status_code} - {dep_res.text}")
        return
    dep_data = dep_res.json()

    # Read active deployment nodes
    staging_node = dep_data.get('staging')
    production_node = dep_data.get('production')

    # Read Expiry Timeframes Natively
    staging_expiry = extract_expiry_date(staging_node)
    production_expiry = extract_expiry_date(production_node)

    # Calculate SAN Differences Matrix
    staging_sans = extract_dns_names_safely(staging_node)
    production_sans = extract_dns_names_safely(production_node)
    only_in_staging = sorted(list(set(staging_sans) - set(production_sans)))
    only_in_production = sorted(list(set(production_sans) - set(staging_sans)))

    # Compute Final Network Alignment State Label
    if not staging_node and not production_node:
        audit_status = "Not Deployed"
    elif only_in_staging or only_in_production:
        audit_status = "Mismatch (Pending Deployment)"
    else:
        audit_status = "In Sync"

    # --- TASK 3: OUTPUT LIVE INTERACTIVE SUMMARY ---
    print("\n" + "-"*65)
    print(f"📊 SYSTEM SNAPSHOT COMPILED FOR ENROLLMENT: {enrollment_id}")
    print(f"   • Common Name (CN) : {cert_name}")
    print(f"   • Certificate Type : {cert_type}")
    print(f"   • Slot Identifier  : {slot_number_str}")
    print(f"   • SNI-Only Option  : {sni_flag}")
    print(f"   • Test on Staging  : {always_test_on_staging}")
    print(f"   • Current Status   : {audit_status}")
    print("-"*65 + "\n")

    record = {
        "Enrollment ID": enrollment_id,
        "Certificate Name (CN)": cert_name,
        "Certificate Type": cert_type,
        "Slot Number": slot_number_str,
        "SNI-Only": sni_flag,
        "Always Test on Staging": always_test_on_staging,
        "Audit Status": audit_status,
        "Staging SAN Count": len(staging_sans),
        "Production SAN Count": len(production_sans),
        "Staging Expiry Date": staging_expiry,
        "Production Expiry Date": production_expiry,
        "SANs Only in Staging (Pending)": ", ".join(only_in_staging) if only_in_staging else "None",
        "SANs Only in Production (Leftover)": ", ".join(only_in_production) if only_in_production else "None",
        "Full Staging DNS Selection": ", ".join(sorted(staging_sans)) if staging_sans else "Empty",
        "Full Production DNS Selection": ", ".join(sorted(production_sans)) if production_sans else "Empty"
    }

    df = pd.DataFrame([record])
    output_filename = f"CPS_Audit_Report_{enrollment_id}.xlsx"
    df.to_excel(output_filename, index=False)
    print(f"🎉 SUCCESS: Comprehensive spreadsheet generated cleanly -> '{output_filename}'")

if __name__ == "__main__":
    run_interactive_audit()