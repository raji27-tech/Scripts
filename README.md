######## Tool --1
# SAN Spectrum 🛡️
> High-Speed Akamai Edge Certificate & SAN Audit Utility

SAN Spectrum is an automated auditing utility designed to streamline peer reviews and eliminate human error during Akamai Edge certificate deployments and renewals. By interfacing directly with Akamai APIs, it instantly extracts enrollment metadata, tracks expiration timelines, and validates DNS resolution across dual networks to ensure zero-downtime cutovers.

## Key Highlights
* **Automated Peer Reviews:** Removes manual validation overhead and risk of human error during certificate changes.
* **Ultra-Fast Performance:** Generates a complete end-to-end certificate audit in **3–5 seconds**.
* **Dual-Network DNS Verification:** Automatically compares Subject Alternative Name (SAN) entries across both Akamai Staging and Production networks to verify edge routing before launch.
* **Partner & Cross-Account Ready:** Requires only an `accountSwitchKey` and `enrollment_id` at runtime to query customer environments securely without hardcoding credentials.

## Audited Data Points
* **Certificate Metadata:** Slot assignments, certificate types, and trust chains.
* **Lifecycle Tracking:** Expiry dates and renewal status.
* **SAN Verification:** Complete list of Subject Alternative Names.
* **Network Alignment:** Live DNS verification comparing Staging vs. Production behavior.


####### Tool --2
# Origin Pulse 📜
> Akamai Property Manager Origin Certificate & Trust Auditor

Origin Pulse is a specialized auditing utility designed to inspect, validate, and track origin certificate configurations across Akamai Property Manager rules. By scanning configurations across accounts, it identifies custom authority certificates, extracts trust settings, and maps certificate expiration timelines to help prevent origin validation failures and unexpected backend outages.

## Key Features
* **Trust Option Validation:** Automatically extracts and reports the exact configuration values set within the "Trust" option across all origin behaviors.
* **Custom CA Inventory:** Identifies, counts, and inventories custom certificates uploaded to the "Custom Authority Certificate" section.
* **Lifecycle & Expiry Tracking:** Provides a clear, detailed breakdown of all uploaded origin certificates alongside their exact expiration dates for proactive renewal management.
* **Account-Wide Auditing:** Scalable execution that sweeps through configurations and origin behaviors across any target Akamai account within a few minutes.

## Audited Data Points
* **Trust Settings:** Configured origin trust model (e.g., Akamai Certificate Store vs. Custom CAs).
* **Certificate Inventory:** Count and list of custom authority certificates per configuration.
* **Lifecycle Status:** Expiration timelines for uploaded origin certificates.
* **Origin Behaviors:** Targeted audit of origin server behaviors embedded across property versions.
########## Script---3
SYF-794BUlkFinal.py has script which helps to do bulk update for every origin server hostname with specific origin certificates upload, Also make sure to update Trust option as "Satisfy One of the below option" & enables both the options(Akamai Certificate Store
& Third Party Certificate Store) under "Akamai-managed Certificate Authority Sets".


########### Tool --4
AkaOriginMapper 

# AkaOriginMapper 🎯
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
