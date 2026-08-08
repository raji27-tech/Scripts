######## Tool --1. SAN Spectrum is a utility script built to simplify the peer review process and eliminate human error when auditing Akamai Edge certificates.

Key Features:

1. Comprehensive Auditing: Extracts certificate slots, types, and expiry dates.
2. DNS Verification: Compares SAN entries across both staging and production networks.
3. User-Friendly: Simply enter your switch key and enrollment ID to generate a complete audit report.
4. Performance: Generates complete audit within 3–5 seconds.



####### Tool --2
Origin Pulse is an auditing utility designed to verify origin certificate statuses within Akamai Property Manager configurations across any account.

Key Features:

1. Trust Validation: Extracts the exact configuration values set in the "Trust" option.
2. Custom Certificate Inventory: Identifies the number of certificates uploaded to the "Custom Authority Certificate" section.
3. Lifecycle Tracking: Provides a clear breakdown of the uploaded certificates along with their respective expiry dates.
4. Performance: Execution time varies depending on the number of configurations and origin behaviors within the account, typically completing within a few minutes.


########## Script---3
SYF-794BUlkFinal.py has script which helps to do bulk update for every origin server hostname with specific origin certificates upload, Also make sure to update Trust option as "Satisfy One of the below option" & enables both the options(Akamai Certificate Store
& Third Party Certificate Store) under "Akamai-managed Certificate Authority Sets".


########### Tool --4
AkaOriginMapper 

# OriginScope 🎯
> Automated Akamai Property Manager (PAPI) Hostname & Origin Exporter
OriginScope is a Python utility designed to audit Akamai Property Manager configurations across a specific Group and Contract. It recursively traverses rule trees to map all edge hostnames and their corresponding origin servers (including default behaviors and child-rule path overrides), then exports a formatted Excel report.
# Key Features
* **Interactive CLI:** Prompts for Group ID, Contract ID, and Account Switch Key at runtime—no hardcoded secrets or credentials.
* **Multi-Account & Partner Support:** Native support for Akamai `accountSwitchKey` to audit customer accounts seamlessly.
* **Deep Rule-Tree Traversal:** Recursively extracts origins defined in nested child rules (path overrides) and NetStorage, not just default behaviors.
* **Environment-Aware Logic:** Prioritizes active **Production** versions, gracefully falling back to **Staging** or draft configurations if inactive.
* **Excel Export:** Auto-formats output into an organized `.xlsx` spreadsheet with auto-adjusted column widths.
# Extracted Data Points
* Property Name
* Active Staging Version
* Active Production Version
* Assigned Hostnames
* Target Origin Servers
# Prerequisites
* Python 3.8+
* Active Akamai API credentials configured in `~/.edgerc` with Property Manager (PAPI) **Read-Only** or **Read-Write** scope.
