import csv
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from akamai.edgegrid import EdgeGridAuth

# -------------------------------------------------------------
# 1. AUTHENTICATION & CLIENT INITIALIZATION
# -------------------------------------------------------------
session = requests.Session()

# Replace with your Akamai API credentials
AKAMAI_HOST = "xxxxx"

session.auth = EdgeGridAuth(
    client_token="xxxxxx",
    client_secret="xxxxx",
    access_token="xxxxx"
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

def analyze_property(prop, group_name, query_params):
    """Processes a single property and returns its report data."""
    prop_id = prop["propertyId"]
    prop_name = prop["propertyName"]
    
    # 1. Get property versions
    versions_url = f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions"
    versions_res = session.get(versions_url, params=query_params)
    
    if versions_res.status_code != 200:
        return None

    versions = versions_res.json().get("versions", {}).get("items", [])
    staging_version = next((v["propertyVersion"] for v in versions if v.get("stagingStatus") == "ACTIVE"), "None")
    prod_version = next((v["propertyVersion"] for v in versions if v.get("productionStatus") == "ACTIVE"), "None")
    
    # Target Prod first, fallback to Staging, then latest
    target_version = prod_version if prod_version != "None" else (staging_version if staging_version != "None" else prop.get("latestVersion"))
    
    missing_certs = list(REQUIRED_SUBJECT_CNS)
    certs_uploaded = "No"
    
    # 2. Fetch rules for the target version
    if target_version and target_version != "None":
        rules_url = f"https://{AKAMAI_HOST}/papi/v1/properties/{prop_id}/versions/{target_version}/rules"
        rules_res = session.get(rules_url, params=query_params)
        
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
        missing_certs = ["No active or latest version found"]

    action_required = "Yes" if missing_certs and missing_certs[0] != "No active or latest version found" else "No"

    return {
        "Group Name": group_name,
        "Config Name": prop_name,
        "Staging Version": staging_version,
        "Prod Version": prod_version,
        "Certs Uploaded": certs_uploaded,
        "Missing Certs": ", ".join(missing_certs) if missing_certs else "None",
        "Action Required": action_required
    }

# -------------------------------------------------------------
# 4. MAIN EXECUTION (ACCOUNT-WIDE & THREADED)
# -------------------------------------------------------------
def generate_account_cert_report():
    print("=== Akamai Account-Wide Origin Certificate Auditor ===")
    account_name = input("Enter Account Name (for reporting): ").strip()
    switch_key = input("Enter Account Switch Key: ").strip()
    
    print(f"\n[INFO] Fetching all groups for Account: {account_name}...")
    groups_endpoint = f"https://{AKAMAI_HOST}/papi/v1/groups"
    base_params = {"accountSwitchKey": switch_key} if switch_key else {}
    
    groups_res = session.get(groups_endpoint, params=base_params)
    if groups_res.status_code != 200:
        print(f"[ERROR] Failed to fetch groups. Status: {groups_res.status_code}")
        return

    group_items = groups_res.json().get("groups", {}).get("items", [])
    print(f"[INFO] Found {len(group_items)} groups. Discovering properties...")

    all_properties_to_scan = []

    # 1. Build a list of all properties across all groups
    for group in group_items:
        group_name = group.get("groupName", "Unknown Group")
        group_id = group.get("groupId")
        
        for contract_id in group.get("contractIds", []):
            query_params = {
                "accountSwitchKey": switch_key,
                "contractId": contract_id,
                "groupId": group_id
            }
            
            props_res = session.get(f"https://{AKAMAI_HOST}/papi/v1/properties", params=query_params)
            if props_res.status_code == 200:
                properties = props_res.json().get("properties", {}).get("items", [])
                for prop in properties:
                    all_properties_to_scan.append((prop, group_name, query_params))

    total_props = len(all_properties_to_scan)
    print(f"[INFO] Discovered {total_props} total properties. Beginning deep scan...")

    report_data = []

    # 2. Process properties concurrently for maximum speed
    # Threading is highly recommended for account-wide runs to prevent hours of sequential API calls.
    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_prop = {
            executor.submit(analyze_property, prop, grp, params): prop["propertyName"]
            for prop, grp, params in all_properties_to_scan
        }
        
        processed_count = 0
        for future in as_completed(future_to_prop):
            prop_name = future_to_prop[future]
            processed_count += 1
            try:
                result = future.result()
                if result:
                    report_data.append(result)
                print(f"[{processed_count}/{total_props}] Scanned: {prop_name}")
            except Exception as e:
                print(f"[ERROR] Failed scanning {prop_name}: {e}")

    # 3. Generate CSV Report
    if report_data:
        report_filename = f"account_cert_audit_{account_name.replace(' ', '_')}.csv"
        with open(report_filename, mode="w", newline="", encoding="utf-8") as csv_file:
            fieldnames = [
                "Group Name", "Config Name", "Staging Version", 
                "Prod Version", "Certs Uploaded", "Missing Certs", "Action Required"
            ]
            writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
            
            writer.writeheader()
            writer.writerows(report_data)

        print("\n" + "="*70)
        print(f"[COMPLETE] Account-wide audit finished. Report generated: {report_filename}")
        print("="*70 + "\n")
    else:
        print("\n[WARN] No property data was gathered.")

if __name__ == "__main__":
    generate_account_cert_report()
