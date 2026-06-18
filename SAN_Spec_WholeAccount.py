import requests
import os
import pandas as pd
from akamai.edgegrid import EdgeGridAuth, EdgeRc

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

def run_account_wide_audit():
    switch_key = input("🔑 Please enter the Akamai Switch Key: ").strip()
    if not switch_key:
        print("❌ ERROR: Switch Key cannot be blank.")
        return

    print("\n⏳ Fetching full account inventory...")
    inv_res = s.get(
        f"https://{baseurl}/cps/v2/enrollments", 
        params={'accountSwitchKey': switch_key},
        headers={'Accept': 'application/vnd.akamai.cps.enrollments.v11+json'}
    )
    
    if inv_res.status_code != 200:
        print(f"❌ Failed: {inv_res.status_code} - {inv_res.text}")
        return

    enrollments = inv_res.json().get('enrollments', [])
    all_records = []

    for enr in enrollments:
        eid = str(enr.get('enrollmentId') or enr.get('id', 'Unknown'))
        if eid == 'Unknown': continue
            
        print(f"🔍 Processing: {eid}")
        
        # Fetch Metadata
        enr_res = s.get(
            f"https://{baseurl}/cps/v2/enrollments/{eid}", 
            params={'accountSwitchKey': switch_key},
            headers={'Accept': 'application/vnd.akamai.cps.enrollment.v11+json'}
        )
        if enr_res.status_code != 200: continue
        data = enr_res.json()
        
        # Fetch Deployments
        dep_res = s.get(
            f"https://{baseurl}/cps/v2/enrollments/{eid}/deployments", 
            params={'accountSwitchKey': switch_key},
            headers={'Accept': 'application/vnd.akamai.cps.deployments.v7+json'}
        )
        if dep_res.status_code != 200: continue
        dep_data = dep_res.json()

        # SAN Comparison Logic
        staging_sans = extract_dns_names_safely(dep_data.get('staging'))
        prod_sans = extract_dns_names_safely(dep_data.get('production'))
        only_in_staging = sorted(list(set(staging_sans) - set(prod_sans)))
        only_in_prod = sorted(list(set(prod_sans) - set(staging_sans)))
        
        # SNI Logic
        net_config = data.get('networkConfiguration', {})
        sni_flag = "On" if (net_config.get('sniOnly') is True or (isinstance(net_config.get('sni'), dict) and net_config.get('sni').get('sniOnly') is True)) else "Off"

        # Construct full record including the SAN comparison fields
        all_records.append({
            "Enrollment ID": eid,
            "Common Name": data.get('csr', {}).get('cn'),
            "Audit Status": "Mismatch (Pending Deployment)" if (only_in_staging or only_in_prod) else "In Sync",
            "SNI-Only": sni_flag,
            "Staging Expiry": extract_expiry_date(dep_data.get('staging')),
            "Production Expiry": extract_expiry_date(dep_data.get('production')),
            "Staging SAN Count": len(staging_sans),
            "Production SAN Count": len(prod_sans),
            "SANs Only in Staging (Pending)": ", ".join(only_in_staging) if only_in_staging else "None",
            "SANs Only in Production (Leftover)": ", ".join(only_in_prod) if only_in_prod else "None",
            "Full Staging DNS Selection": ", ".join(sorted(staging_sans)),
            "Full Production DNS Selection": ", ".join(sorted(prod_sans))
        })

    pd.DataFrame(all_records).to_excel("Master_Account_Audit_Report.xlsx", index=False)
    print("\n🎉 SUCCESS: Report saved as 'Master_Account_Audit_Report.xlsx'")

if __name__ == "__main__":
    run_account_wide_audit()