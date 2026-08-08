import os
import requests
import pandas as pd
from akamai.edgegrid import EdgeGridAuth, EdgeRc

def extract_origins(rule_node):
    """Recursively search for origins in rule trees (handles child rules & path overrides)."""
    origins = []
    for behavior in rule_node.get("behaviors", []):
        if behavior.get("name") == "origin":
            opts = behavior.get("options", {})
            origin_type = opts.get("originType", "CUSTOMER")
            if origin_type == "CUSTOMER":
                origins.append(opts.get("hostname", "N/A"))
            elif origin_type == "NET_STORAGE":
                origins.append(opts.get("netStorage", {}).get("downloadDomainName", "NetStorage"))
            else:
                origins.append(opts.get("hostname", origin_type))
                
    for child in rule_node.get("children", []):
        origins.extend(extract_origins(child))
    return list(set(origins))

def main():
    print("=== Akamai Property Inventory Fetcher ===")
    group_id = input("Enter Akamai Group ID (e.g., grp_214399): ").strip()
    contract_id = input("Enter Akamai Contract ID (e.g., ctr_G-2DD8FPF): ").strip()
    account_switch_key = input("Enter Account Switch Key (press Enter to skip): ").strip()
    
    if not group_id or not contract_id:
        print("Error: Group ID and Contract ID are required.")
        return

    # Load authentication credentials from ~/.edgerc
    edgerc_path = os.path.expanduser("~/.edgerc")
    if not os.path.exists(edgerc_path):
        print(f"Error: Could not find edgerc file at {edgerc_path}")
        return

    try:
        edgerc = EdgeRc(edgerc_path)
        base_url = f"https://{edgerc.get('default', 'host')}"
        
        session = requests.Session()
        session.auth = EdgeGridAuth.from_edgerc(edgerc_path, "default")
    except Exception as e:
        print(f"Authentication setup failed: {e}")
        return

    # Construct request query parameters
    query_params = {
        "groupId": group_id,
        "contractId": contract_id
    }
    if account_switch_key:
        query_params["accountSwitchKey"] = account_switch_key

    print(f"\nFetching properties for Group: {group_id}, Contract: {contract_id}...")
    
    # 1. Fetch properties in group
    props_url = f"{base_url}/papi/v1/properties"
    res = session.get(props_url, params=query_params)
    
    if res.status_code != 200:
        print(f"API Error ({res.status_code}): {res.text}")
        return
        
    properties = res.json().get("properties", {}).get("items", [])
    print(f"Found {len(properties)} properties. Extracting hostnames and origins...\n")
    
    inventory = []
    
    for prop in properties:
        p_id = prop["propertyId"]
        p_name = prop["propertyName"]
        
        staging_version = prop.get("stagingVersion")
        production_version = prop.get("productionVersion")
        latest_version = prop.get("latestVersion")
        
        # Priority: Production > Staging > Latest Draft
        target_version = production_version or staging_version or latest_version
        
        if not target_version:
            continue

        # 2. Fetch hostnames
        host_url = f"{base_url}/papi/v1/properties/{p_id}/versions/{target_version}/hostnames"
        h_res = session.get(host_url, params=query_params)
        hostnames = []
        if h_res.status_code == 200:
            hostnames = [item["cnameFrom"] for item in h_res.json().get("hostnames", {}).get("items", [])]

        # 3. Fetch rules tree and extract origin hostnames
        rules_url = f"{base_url}/papi/v1/properties/{p_id}/versions/{target_version}/rules"
        r_res = session.get(rules_url, params=query_params)
        origins = []
        if r_res.status_code == 200:
            origins = extract_origins(r_res.json().get("rules", {}))

        # Format record for report
        inventory.append({
            "Property Name": p_name,
            "Active Staging Version": staging_version if staging_version else "Not Active",
            "Active Production Version": production_version if production_version else "Not Active",
            "Hostnames": ",\n".join(hostnames) if hostnames else "None",
            "Origin Servers": ",\n".join(origins) if origins else "None"
        })
        
        print(f"Processed: {p_name}")

    if not inventory:
        print("No inventory data retrieved.")
        return

    # 4. Generate Excel Output
    df = pd.DataFrame(inventory)
    excel_filename = f"Akamai_Inventory_{group_id}.xlsx"
    
    with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
        df.to_excel(writer, index=False, sheet_name='Inventory')
        worksheet = writer.sheets['Inventory']
        for idx, col in enumerate(df.columns):
            max_len = max(df[col].astype(str).map(len).max(), len(col)) + 2
            worksheet.column_dimensions[chr(65 + idx)].width = min(max_len, 50)

    print(f"\n✅ Data successfully exported to {excel_filename}")

if __name__ == "__main__":
    main()
