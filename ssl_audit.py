import pandas as pd
import warnings
from cryptography import x509
from cryptography.x509.oid import NameOID
from sslyze import (
    Scanner,
    ServerNetworkLocation,
    ScanCommand,
    ServerScanRequest,
    ServerScanStatusEnum,
)

# Silence warnings for a clean professional output
warnings.filterwarnings("ignore", category=UserWarning, module="sslyze")
warnings.filterwarnings("ignore", category=DeprecationWarning, module="cryptography")

def is_wildcard_cert(cert):
    """Checks for asterisk in Common Name or SANs."""
    try:
        common_names = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        for cn in common_names:
            if "*" in str(cn.value):
                return "Yes (CN)"

        try:
            san_ext = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            dns_names = san_ext.value.get_values_for_type(x509.DNSName)
            for name in dns_names:
                if "*" in name:
                    return "Yes (SAN)"
        except x509.ExtensionNotFound:
            pass
    except Exception:
        return "Unknown"
    return "No"

def audit_ssl(domains):
    results_list = []
    
    commands = {
        ScanCommand.CERTIFICATE_INFO,
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
        ScanCommand.HEARTBLEED,
    }

    scan_requests = [
        ServerScanRequest(server_location=ServerNetworkLocation(hostname=d, port=443), scan_commands=commands)
        for d in domains
    ]

    print(f"[*] Executing deep SSL/TLS audit for {len(scan_requests)} targets...")
    scanner = Scanner()
    scanner.queue_scans(scan_requests)

    for result in scanner.get_results():
        domain = result.server_location.hostname
        print(f"[+] Analyzing: {domain}")

        if result.scan_status == ServerScanStatusEnum.ERROR_NO_CONNECTIVITY:
            results_list.append({"Domain": domain, "Status": "Connectivity Error"})
            continue

        try:
            scan_res = result.scan_result
            cert_info = scan_res.certificate_info.result
            cert_deployment = cert_info.certificate_deployments[0]
            leaf_cert = cert_deployment.received_certificate_chain[0]
            
            # --- Advanced Protocol & Cipher Analysis ---
            supported_versions = []
            all_ciphers = []
            weak_ciphers = []

            # Mapping for all standard protocols
            protocols = [
                ('SSL 2.0', scan_res.ssl_2_0_cipher_suites),
                ('SSL 3.0', scan_res.ssl_3_0_cipher_suites),
                ('TLS 1.0', scan_res.tls_1_0_cipher_suites),
                ('TLS 1.1', scan_res.tls_1_1_cipher_suites),
                ('TLS 1.2', scan_res.tls_1_2_cipher_suites),
                ('TLS 1.3', scan_res.tls_1_3_cipher_suites),
            ]

            for proto_name, proto_res in protocols:
                if proto_res and proto_res.result and proto_res.result.accepted_cipher_suites:
                    supported_versions.append(proto_name)
                    for suite in proto_res.result.accepted_cipher_suites:
                        c_name = suite.cipher_suite.name
                        cipher_entry = f"{proto_name}: {c_name}"
                        all_ciphers.append(cipher_entry)
                        
                        # Identify Weakness (MD5, RC4, 3DES, CBC, SHA1)
                        if any(kw in c_name for kw in ["RC4", "3DES", "CBC", "MD5", "SHA1", "NULL", "anon"]):
                            weak_ciphers.append(cipher_entry)

            # --- Construct Data Row ---
            data = {
                "Domain": domain,
                "Status": "Success",
                "Is Wildcard": is_wildcard_cert(leaf_cert),
                "Supported TLS Versions": ", ".join(supported_versions),
                "Issuer": leaf_cert.issuer.rfc4514_string(),
                "Expiration (UTC)": leaf_cert.not_valid_after_utc.isoformat(),
                "Key Size": leaf_cert.public_key().key_size,
                "Signature Algorithm": leaf_cert.signature_algorithm_oid._name,
                "Heartbleed": "VULNERABLE" if scan_res.heartbleed.result.is_vulnerable_to_heartbleed else "Safe",
                "Weak Ciphers Found": "\n".join(weak_ciphers) if weak_ciphers else "None",
                "All Supported Ciphers": "\n".join(all_ciphers),
            }
            results_list.append(data)

        except Exception as e:
            print(f" [!] Error parsing {domain}: {e}")
            results_list.append({"Domain": domain, "Status": f"Parsing Error: {str(e)}"})

    # --- Structured Excel Export ---
    if results_list:
        df = pd.DataFrame(results_list)
        output_file = "full_ssl_pentest_report.xlsx"
        with pd.ExcelWriter(output_file, engine='openpyxl') as writer:
            df.to_excel(writer, index=False, sheet_name='SSL Audit')
            
            # Format columns for professional readability
            worksheet = writer.sheets['SSL Audit']
            for col in worksheet.columns:
                max_len = 0
                column = col[0].column_letter
                for cell in col:
                    try:
                        if len(str(cell.value)) > max_len:
                            max_len = len(str(cell.value))
                    except: pass
                # Adjust width with a 60-character cap to keep it manageable
                worksheet.column_dimensions[column].width = min(max_len + 2, 60)

        print(f"\n[SUCCESS] Final comprehensive report generated: {output_file}")

if __name__ == "__main__":
    # Add your assessment targets here
    targets = ["google.com","exampledomain.com"]
    audit_ssl(targets)
