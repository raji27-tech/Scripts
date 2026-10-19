import csv
import requests
from akamai.edgegrid import EdgeGridAuth

# -------------------------------------------------------------
# 1. AUTHENTICATION & CLIENT INITIALIZATION
# -------------------------------------------------------------
session = requests.Session()

# Replace with your Akamai API credentials
AKAMAI_HOST = "xxxx"

session.auth = EdgeGridAuth(
    client_token="xxx",
    client_secret="xxxx",
    access_token="xxxx"
)

# -------------------------------------------------------------
# 2. REQUIRED CERTIFICATES DEFINITION
# -------------------------------------------------------------
REQUIRED_SUBJECT_CNS = {
    "Synchrony Issuing CA",
    "Synchrony Issuing CA - G4",
    "Synchrony Issuing CA - G2",
    "Internal Hostnames Root CA 1",
    "Synchrony Root CA - G4"
}

# -------------------------------------------------------------
# 3. HELPER FUNCTIONS
# -------------------------------------------------------------
def find_custom_certs_in_rules(node):
    """Recursively search the rule tree for custom origin certificates."""
    found_certs = set()
    
    if "behaviors" in node:
        for behavior in node["behaviors"]:
            if behavior.get("name") == "origin":
                options = behavior.get("options", {})
                if options.get("originType") == "CUSTOMER":
                    custom_cas = options.get("customCertificateAuthorities", [])
                    for ca in custom_cas:
                        if isinstance(ca, dict) and "subjectCN" in ca:
                            found_certs.add(ca["subjectCN"])
                            
    if "children" in node:
        for child in node["children"]:
            found_certs.update(find_custom_certs_in_rules(child))
            
    return found_certs

# -------------------------------------------------------------
# 4. MAIN EXECUTION & REPORT GENERATION
# -------------------------------------------------------------
def generate_cert_report():
    print("=== Akamai Origin Certificate Auditor ===")
    switch_key = input("Enter Account Switch Key: ").strip()
    group_input = input("Enter Group Name or Group ID: ").strip()
    
    # 1. Fetch all groups to find the matching Group ID and Contract IDs
    print("\n[INFO] Fetching group structures...")
    groups_endpoint = f"https://{AKAMAI_HOST}/papi/v1/groups"
    params = {"accountSwitchKey": switch_key} if switch_key else {}
    
    groups_res = session.get(groups_endpoint, params=params)
    if groups_res.status_code != 200:
        print(f"[ERROR] Failed to fetch groups. Status: {groups_res.status_code}")
        return

    group_items = groups_res.json().get("groups", {}).get("items", [])
    target_group = next(
        (g for g in group_items if g.get("groupId") == group_input or g.get("groupName") == group_input), 
        None
    )
    
    if not target_group:
        print(f"[ERROR] Could not find a group matching '{group_input}'.")
        return
        
    group_id = target_group.get("groupId")
    contract_ids = target_group.get("contractIds", [])
    print(f"[SUCCESS] Found Group: {target_group.get('groupName')} (ID: {group_id})")

    report_data = []

    # 2. Iterate through contracts and properties
    for contract_id in contract_ids:
        query_params = {
            "accountSwitchKey": switch_key,
            "contractId": contract_id,
            "groupId": group_id
        }
        
        props_res = session.get(f"https://{AKAMAI_HOST}/papi/v1/properties", params=query_params)
        if props_res.status_code != 200:
            continue
            
        properties = props_res.json().get("properties", {}).get("items", [])
        
        for prop in properties:
            prop_id = prop["propertyId"]
            prop_name = prop["propertyName"]
            print(f"[SCANNING] Property: {prop_name}")
            
            # 3. Get property versions to find ACTIVE Staging and Prod versions
            versions_res = session.get(f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions", params=query_params)
            if versions_res.status_code != 200:
                continue
                
            versions = versions_res.json().get("versions", {}).get("items", [])
            staging_version = next((v["propertyVersion"] for v in versions if v.get("stagingStatus") == "ACTIVE"), "None")
            prod_version = next((v["propertyVersion"] for v in versions if v.get("productionStatus") == "ACTIVE"), "None")
            
            # Determine which version's rules to analyze (Prefer Prod, fallback to Staging, fallback to latest)
            target_version = prod_version if prod_version != "None" else (staging_version if staging_version != "None" else prop.get("latestVersion"))
            
            missing_certs = list(REQUIRED_SUBJECT_CNS) # Default to all missing if no rules found
            certs_uploaded = "No"
            
            # 4. Fetch rules for the target version and evaluate certs
            if target_version and target_version != "None":
                rules_res = session.get(f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions/{target_version}/rules", params=query_params)
                
                if rules_res.status_code == 200:
                    rules_tree = rules_res.json().get("rules", {})
                    found_certs = find_custom_certs_in_rules(rules_tree)
                    
                    missing_certs_set = REQUIRED_SUBJECT_CNS - found_certs
                    missing_certs = list(missing_certs_set)
                    
                    if not missing_certs:
                        certs_uploaded = "Yes"
                    elif len(missing_certs) < len(REQUIRED_SUBJECT_CNS):
                        certs_uploaded = "Partial"
            else:
                missing_certs = ["No active or latest version found to scan"]

            report_data.append({
                "Config Name": prop_name,
                "Staging Version": staging_version,
                "Prod Version": prod_version,
                "Certs Uploaded": certs_uploaded,
                "Missing Certs": ", ".join(missing_certs) if missing_certs else "None"
            })

    # 5. Generate CSV Report
    report_filename = "certificate_audit_report.csv"
    with open(report_filename, mode="w", newline="", encoding="utf-8") as csv_file:
        fieldnames = ["Config Name", "Staging Version", "Prod Version", "Certs Uploaded", "Missing Certs"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        
        writer.writeheader()
        writer.writerows(report_data)

    print("\n" + "="*60)
    print(f"[COMPLETE] Audit finished. Report generated: {report_filename}")
    print("="*60 + "\n")

if __name__ == "__main__":
    generate_cert_report()
