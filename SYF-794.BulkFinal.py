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
AKAMAI_HOST = "akab-x3w2uf72jso4owfn-mvw3wpwac5urwwqu.luna.akamaiapis.net"

session.auth = EdgeGridAuth(
    client_token="akab-qaznsfvzbrq5cnnq-rotkxfhe5ymu4qif",
    client_secret="fYOHH11RH7jepbkZjVb2CujZxleMLAb0uE/nXPrNu3Y=",
    access_token="akab-7t7zuu4riy5pr7ni-z5qy44mk5mg65bki"
)

# -------------------------------------------------------------
# 2. TARGET CONFIGURATION DEFINITIONS
# -------------------------------------------------------------
# Define the collection of property targets to scan and modify globally
TARGET_PROPERTY_NAMES = [
       "nonprod.synchronyincubation.com",
       "Ecarts_Non-Prod"
]

SWITCH_KEY = "F-AC-1787020:1-2RBL"
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
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
sKSe/zpBJ2wdrKRd+gUpkNCPyq5vyms=
-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Synchrony Issuing CA - G4",
        "notBefore": 1726501068000,
        "notAfter": 2042033868000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----
MIIC/TCCAoOgAwIBAgIUXVVP0H8p+rkHG1Uu5x/jsItIppkwCgYIKoZIzj0EAwMw
QjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN5bmNocm9ueTEfMB0GA1UEAwwWU3lu
Y2hyb255IFJvb3QgQ0EgLSBHNDAeFw0yNDA5MTYxNTM3NDhaFw0zNDA5MTYxNTM3
NDhaMEUxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlTeW5jaHJvbnkxIjAgBgNVBAMM
GVN5bmNocm9ueSBJc3N1aW5nIENBIC0gRzQwdjAQBgcqhkjOPQIBBgUrgQQAIgNi
AAQsmqzWy8MEuvJIwEr415aRWrVL3WeaNfYVg3qaLqBWPIkYETVveehAnsDazQ0Z
h/WYPvQGX/Ma4qB4ggMc5ZQ8XOUzys5bs5tMHnQgtsatfSrz4dEKnh2E31REgAZO
1zejggE1MIIBMTAOBgNVHQ8BAf8EBAMCAYYwEgYDVR0TAQH/BAgwBgEB/wIBATAf
BgNVHSMEGDAWgBQlHexOnenLZ7JFagvvptO9yhyzJTAdBgNVHQ4EFgQU8V7MvOCd
LpweYYOV6KXNwdA4h0IwRwYDVR0fBEAwPjA8oDqgOIY2aHR0cDovL2NybC5pbnRl
cm5hbGhvc3RuYW1lcy5jb20vU3luY2hyb255Uk9PVENBRzQuY3JsMIGBBggrBgEF
BQcBAQR1MHMwQgYIKwYBBQUHMAKGNmh0dHA6Ly9jcmwuaW50ZXJuYWxob3N0bmFt
ZXMuY29tL1N5bmNocm9ueVJPT1RDQUc0LmNydDAtBggrBgEFBQcwAYYhaHR0cDov
L29jc3AuaW50ZXJuYWxob3N0bmFtZXMuY29tMAoGCCqGSM49BAMDA2gAMGUCMGNJ
wjVg/qg3u9IFVQTGG68YE5EBMixzrkaepitJm6m9uvn08NlEEKvwN8CkgXr+HQIx
APrZmqbdLOoUwM1sy1Pa5E73GtmZ3aIZ6Bv2dNpMPbkABHHkMKz1a5Wr9a29pOnt
Ug==
-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Synchrony Issuing CA - G2",
        "notBefore": 1726501281000,
        "notAfter": 2042034081000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----
MIIGVDCCBDygAwIBAgIUG12IGAOLY6AI1l9W42MplE7+MfowDQYJKoZIhvcNAQEL
BQAwUTELMAkGA1UEBhMCVVMxGzAZBgNVBAoMEkludGVybmFsIEhvc3RuYW1lczEl
MCMGA1UEAwwcSW50ZXJuYWwgSG9zdG5hbWVzIFJvb3QgQ0EgMTAeFw0yNDA5MTYx
NTQxMjFaFw0zNDA5MTYxNTQxMjFaMEUxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlT
eW5jaHJvbnkxIjAgBgNVBAMMGVN5bmNocm9ueSBJc3N1aW5nIENBIC0gRzIwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCag79BYJgwHXIUZsLjYze9+G0A
v0dvhtTVTnLwnPH65r/FD+/LqoQKDVjd7pajsEhN+lr469eCa+YGWavKmVUuqLBu
tcqe9p3CZ6c4kg/vslpwjrXv3r4VCGtK3WwJCdV2/RQIenELN5akPYHVWQFYTCMY
OvE0Nasl9gAItUmItG0tUCcb8t4I8kDhfVbDXKvlSzxunZZGYRbiwkH4P2s/r6Jg
Z1Me6DofIgSRhlwKTFRHCvTNeOtYartY0ysyAb6/2RUBXeQZO75onVeMxmUUHCQM
lIxY2VqJoSUliyY8mDj9Zx8vNuoGkEAPch0xeHb/1L1bspLdJek3A99a/kQ3wNDs
M4B4tW6ZEMDMboyy+RODYHqpQ9BlAe54wQh1pEKIU/8HEM0KSXa8XWiv6kCFby/s
/w+JbTYDwELJn/L87upOb+ryDOLqzc8lIhFI6JMW+sv994hUysB983APQnYgAapt
f1XGXUbsEJ6aPp6OzX9gIGRK1mk+O/wuNvvuKDDJpfrSta/Y+rxy9VWZSslJEWVQ
gLndIgl7BHfEhd+z+zyzosuWpBXzrKEA99n1wQQwDdrVLVUnKU4gTW80NMH9C/3S
kpIBM3F+1mfRCw/I5WE8CWlQtkG9pxqg1v46oDrOdPSp7fIujInfVa0SwjyacQtY
/5jv5ei8fmYK764AIwIDAQABo4IBLjCCASowDgYDVR0PAQH/BAQDAgGGMBIGA1Ud
EwEB/wQIMAYBAf8CAQEwHwYDVR0jBBgwFoAUpP05Vca1tqugQH51XjVr6q++7oYw
HQYDVR0OBBYEFFCAlPBSUbdQ2bZCxayWcA8u368PMEQGA1UdHwQ9MDswOaA3oDWG
M2h0dHA6Ly9jcmwuaW50ZXJuYWxob3N0bmFtZXMuY29tL0lOVEhPU1RST09UQ0Ex
LmNybDB+BggrBgEFBQcBAQRyMHAwPwYIKwYBBQUHMAKGM2h0dHA6Ly9jcmwuaW50
ZXJuYWxob3N0bmFtZXMuY29tL0lOVEhPU1RST09UQ0ExLmNydDAtBggrBgEFBQcw
AYYhaHR0cDovL29jc3AuaW50ZXJuYWxob3N0bmFtZXMuY29tMA0GCSqGSIb3DQEB
CwUAA4ICAQBoliaNWjXLYvccQOUmZbWvPVp9jGIazR/s3h3bymziDZhf2Ke9WOG4
iDT1hKbcHKc3efs8FQ4XHFeT4aI234GkdudEQR5/TsOUB4CY2YIjIOOX4UiEpqhM
0kRhZCKuwCWzpQtd2nNYVB0Ymn7UNz/Luyj4OJ4RWk/gTTyDQNb6k7sUwE5VU5pU
0QTJ2fyB5aFQDe+AqLeW9cK1xozg8vp6hUfeyfexe6xScbdI0qS0jbOqxtwk6ACw
1yS+vRO5Z+zs+pZkB0n5A0fssHwkcdBUsXyhJEG3l3EI/8e3zeG4MtxCSC2znPuW
KQzkeyhx0C/gsLy+BoMCEEn3hurXbRpsTJZn9HH9pdgx/xIpYk3Z9bF02BrZKs2/
uCVePvbo5Wfe4JdkP+jZ2Vw6J0ZPhXeDdBN54jEnaTuAH4y/+SIFFvfogHGWhhcT
lXNVMw5g+WIasPu8bF+EJE8AvqkpLHLIC/v0T9nUcpTNztI/4qv+YUHFubajF6GN
+6KIWtLcJdJtg4i0GjCeVx+3wR31lqyXNRVz+L127rozfDNMo8f+has489REHTGb
fGELzH5llH9sz7p3mxtweUcOmFghsDBtl0kkrHIOkWj3hPtCPiuMGyDXQGXrtdPv
aGGoj3sgNK9STZo81fUpCbGf1RN46sA5+XAt9SDiTJvuIovYM8sAsA==
-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Internal Hostnames Root CA 1",
        "notBefore": 1454690793000,
        "notAfter": 2085842793000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----
MIIFhzCCA2+gAwIBAgIIQBfvQRFn61EwDQYJKoZIhvcNAQELBQAwUTELMAkGA1UE
BhMCVVMxGzAZBgNVBAoMEkludGVybmFsIEhvc3RuYW1lczElMCMGA1UEAwwcSW50
ZXJuYWwgSG9zdG5hbWVzIFJvb3QgQ0EgMTAeFw0xNjAyMDUxNjQ2MzNaFw0zNjAy
MDUxNjQ2MzNaMFExCzAJBgNVBAYTAlVTMRswGQYDVQQKDBJJbnRlcm5hbCBIb3N0
bmFtZXMxJTAjBgNVBAMMHEludGVybmFsIEhvc3RuYW1lcyBSb290IENBIDEwggIi
MA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQC7qdnSiPrXAu67r4qASOpJtnj4
eOLsvzY98Kltd6MF1j5PeQd7VO5Jl/cuCoHDC3Dq/PneI6JoGE6200Ai9uPlcoN8
jKdwmftpi4zvs70kqFJ1rYuSPlD7yDqwU3E5wMF606J2ocDSR2FR6OWpVTbkTwll
SYZRD/pWDItsAUrUNuZfLHzZXY/xOqNH5Jug4tOfPK5ciuB45+lZ5IQnb/XZSpYS
PNGMdNLnPzm9Vd6dg9uIYb43Mbi7LzWlou0C5i4JVfhXlI5UKDqMALBbHQ51FrJU
q90y48JIKJdG2xrmikGqWcSjXShPFZ+BGvarALmNUIUi0J1hCYAL94kcfWxehPPi
Py82OHmzYdJKTyDkCke1qqocxSAes36/B1lMO8bRZPmb4lZPqN/5yPJYOSW++WHo
PIzCXEN948AouQmXk4o33Z4H0TFnxh6RMAHAQyWULlTkvSUCOJ1KzpQDcarebEOS
ziYkDtat5Bh7uMO9B3o03GX7CFxYj5gLrehBXhIfzMybuMh7miM1S0tZ7CvscIQH
OLGsgga2jtCkZ2mMbzuVJAABF2IlMX613hdvFZnorPuweOp1mE31e63JYkpV/l1v
kmRjlh+y5SdBNImHaBxypVJGJ8Bc8gPKSn59HTCuA+qb2GZEBsWH4IY+kWhzS0rU
y8YnTjjRznEospKIHQIDAQABo2MwYTAdBgNVHQ4EFgQUpP05Vca1tqugQH51XjVr
6q++7oYwDwYDVR0TAQH/BAUwAwEB/zAfBgNVHSMEGDAWgBSk/TlVxrW2q6BAfnVe
NWvqr77uhjAOBgNVHQ8BAf8EBAMCAYYwDQYJKoZIhvcNAQELBQADggIBADHgjGxY
WqcnPyaApAhgTu1l0nYjjpptImvkGlm60yQ2WU3+4TFtbeIjBA1SujT1wAmn8sSA
c5g+vl24nyhv59yLA7zx/fKS37qJehJjX506NVIQ4EsF+KbB/spPdLr6CKLTftce
yrlju6o1qPDP7w1KGAd2ZKVqrXoaAB3afQbTqmhuX/RcOdsencfNvR8HvNmvT6cJ
Vv1BSJ4S/jHYDGqg8HQTx9Iw6Ju/rcA28hEKUUOQsmp+cocrtOl+C/mCKraVIGPN
ZY0Qahtsmm3wAHKa6TC/WG9UwKsPnnBDG+N7uabwYFhgEwSYpPK7kHqRCGXALhnl
Lv2CrN2yzDWH0eVR23WaVCfRlsK20WTeIlGB+ghp6Ar/nxN2Yg1zELXKnIPbErg8
F7k8/a+LHBjl62UUmfPw0mQrshru9ZmgTG6rVhcjvO43MverYnRDF34r6GeP8RSr
CzKSZjfM2Hkr2eapk2TLuFa+oD2ZsBIyZSc5AAQ0lof42a0dM5JUfWCC4SCFS3Ht
AZ6nCRJ1vsZACkKYnzAwbrwdcfP1n0xMYClGdYN30IIB+L13POEZ1PPS0v2uSvyE
H7Vnub1gUkH6yh6Ed6ekmX4REG8cuCvEJ4dIW7+50b6GR+dgz+xYLAvB+Q9PllKY
WS0Uuh7T+zH1k/9DM8C1bU8+WOU5nZR9XKMc
-----END CERTIFICATE-----"""
    },
    {
        "subjectCN": "Synchrony Root CA - G4",
        "notBefore": 1726501002000,
        "notAfter": 2515419402000,
        "pemEncodedCert": """-----BEGIN CERTIFICATE-----
MIICJTCCAaygAwIBAgIUU8CpK49fAWdGFv2CcX098ZlIjQowCgYIKoZIzj0EAwMw
QjELMAkGA1UEBhMCVVMxEjAQBgNVBAoMCVN5bmNocm9ueTEfMB0GA1UEAwwWU3lu
Y2hyb255IFJvb3QgQ0EgLSBHNDAeFw0yNDA5MTYxNTM2NDJaFw00OTA5MTYxNTM2
NDJaMEIxCzAJBgNVBAYTAlVTMRIwEAYDVQQKDAlTeW5jaHJvbnkxHzAdBgNVBAMM
FlN5bmNocm9ueSBSb290IENBIC0gRzQwdjAQBgcqhkjOPQIBBgUrgQQAIgNiAATV
l8+ie//IGwdvBMNfQH7VuwsOgAV6yp4+Y0/4SEeUozfzYjs6e0aHgazvsIs5A+0W
91/qaPqBRPfcVC9vOqHhTTyz57OQ7rgU8QtkxqEH/mqF3l8sOhm9WpBpBcShPfKj
YzBhMA4GA1UdDwEB/wQEAwIBhjAPBgNVHRMBAf8EBTADAQH/MB8GA1UdIwQYMBaA
FCUd7E6d6ctnskVqC++m073KHLMlMB0GA1UdDgQWBBQlHexOnenLZ7JFagvvptO9
yhyzJTAKBggqhkjOPQQDAwNnADBkAjBdm+hYYmJHlWH5QzALE7oRQ3uKO5tswsXJ
1LmpO2efvmcY8FYc1V1s80xn99wWp18CMDse391m5/DslGEN20+lsBFkNLyW3Y97
Sdvm6zpwX2zpSPM7icdTkXn+ahgRvbG5Aw==
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