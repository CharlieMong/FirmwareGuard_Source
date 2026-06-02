"""
FirmwareGuard — Finding Knowledge Base
Maps every finding title to rich contextual information shown when a user
clicks a finding row in the GUI or the HTML report.
"""

# Each entry:
#   "Finding title" : {
#       "description" : str   — what this finding means
#       "impact"      : str   — what an attacker can do with it
#       "remediation" : str   — how to fix it
#       "references"  : list  — CWE / CVE / OWASP / NIST links (displayed as text)
#       "cvss"        : str   — approximate CVSS score range
#   }

KNOWLEDGE_BASE = {

    # ── Credentials ──────────────────────────────────────────────────────────
    "Hardcoded password": {
        "description": (
            "A password value appears to be embedded directly in the firmware binary or "
            "a configuration file. Hardcoded credentials are a common and critical security "
            "weakness in embedded firmware — they cannot be changed by end-users and once "
            "discovered are trivially exploited at scale across all devices running this firmware."
        ),
        "impact": (
            "An attacker who extracts the firmware can recover the credential with basic "
            "string analysis tools. They can then authenticate to any device running this "
            "firmware — remotely if a network service is exposed, or locally via serial/JTAG. "
            "This is a primary attack vector for IoT botnet recruitment (e.g. Mirai)."
        ),
        "remediation": (
            "• Never embed credentials in source code or firmware images.\n"
            "• Generate unique, random credentials per device at provisioning time.\n"
            "• Store credentials in write-protected, encrypted non-volatile storage (e.g. eFuse, TPM).\n"
            "• Use certificate-based or token-based authentication instead of passwords.\n"
            "• Force credential change on first boot."
        ),
        "references": [
            "CWE-798: Use of Hard-coded Credentials — https://cwe.mitre.org/data/definitions/798.html",
            "OWASP Firmware Top 10 — I1: Weak, Guessable, or Hardcoded Passwords",
            "NIST SP 800-193 — Platform Firmware Resiliency",
        ],
        "cvss": "9.8 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    },

    "Hardcoded passwd": {
        "description": (
            "A 'passwd' field with a value was found embedded in the firmware. This follows "
            "the same pattern as hardcoded passwords and represents a critical credential exposure."
        ),
        "impact": (
            "Identical to hardcoded password exposure — any device running this firmware "
            "shares the same credential and can be compromised once it is extracted."
        ),
        "remediation": (
            "• Remove all hardcoded passwd fields from firmware.\n"
            "• Use per-device provisioning and secure credential storage.\n"
            "• Rotate any exposed credentials immediately across affected devices."
        ),
        "references": [
            "CWE-798: Use of Hard-coded Credentials — https://cwe.mitre.org/data/definitions/798.html",
        ],
        "cvss": "9.8 (Critical)",
    },

    "Hardcoded secret": {
        "description": (
            "A field named 'secret' with an assigned value was detected. This may be a shared "
            "HMAC secret, session signing key, or application secret key embedded in the firmware."
        ),
        "impact": (
            "If this is a signing or HMAC secret, an attacker can forge tokens, bypass "
            "integrity checks, or impersonate any party in the system. If it is a symmetric "
            "encryption key, all encrypted data can be decrypted."
        ),
        "remediation": (
            "• Rotate the exposed secret immediately.\n"
            "• Use hardware key storage (TPM, HSM, secure enclave) for cryptographic secrets.\n"
            "• Never embed secrets in firmware; inject them at provisioning via a secure channel."
        ),
        "references": [
            "CWE-321: Use of Hard-coded Cryptographic Key — https://cwe.mitre.org/data/definitions/321.html",
            "CWE-798: Use of Hard-coded Credentials",
        ],
        "cvss": "9.1 (Critical)",
    },

    "API key": {
        "description": (
            "An API key string was found embedded in the firmware. API keys grant programmatic "
            "access to third-party services (cloud platforms, payment processors, analytics, etc.) "
            "and must be treated with the same care as passwords."
        ),
        "impact": (
            "Extracted API keys can be used to consume paid services at the firmware vendor's "
            "expense, access or exfiltrate data, pivot to cloud resources, or abuse "
            "rate limits. Keys with write permission can destroy or modify backend data."
        ),
        "remediation": (
            "• Revoke the exposed API key immediately via the service's dashboard.\n"
            "• Issue a new key and deliver it to devices through a secure update or provisioning channel.\n"
            "• Use scoped, read-only keys with IP restrictions where possible.\n"
            "• Store keys in secure, encrypted NVRAM or a hardware security module."
        ),
        "references": [
            "CWE-798: Use of Hard-coded Credentials",
            "OWASP — Secrets Management Cheat Sheet",
        ],
        "cvss": "7.5–9.8 depending on key scope",
    },

    "Authentication token": {
        "description": (
            "A long token string matching the pattern of an authentication or session token "
            "was found in the firmware. This may be a bearer token, JWT secret, or OAuth token "
            "that provides direct API or service access."
        ),
        "impact": (
            "Bearer tokens can be used directly to authenticate to services without further "
            "credentials. If the token is long-lived or never expiring, this provides permanent "
            "access to the associated account or service."
        ),
        "remediation": (
            "• Invalidate the found token immediately.\n"
            "• Replace with short-lived tokens issued at runtime via secure channels.\n"
            "• Implement token rotation and expiry policies."
        ),
        "references": [
            "CWE-522: Insufficiently Protected Credentials",
            "OWASP — JWT Security Cheat Sheet",
        ],
        "cvss": "8.1 (High)",
    },

    "Private key reference": {
        "description": (
            "A reference to a private key (e.g. private_key= or privateKey=) was found in the "
            "firmware, suggesting a private cryptographic key may be stored nearby or the "
            "firmware directly references an embedded key."
        ),
        "impact": (
            "Compromise of a TLS private key allows decryption of all past and future traffic "
            "(if forward secrecy is not used), server impersonation, and man-in-the-middle attacks. "
            "Compromise of a code-signing key undermines the entire update security chain."
        ),
        "remediation": (
            "• Move all private keys out of firmware into hardware key storage (TPM, HSM).\n"
            "• Revoke and reissue any exposed certificates.\n"
            "• Use certificate pinning with a device-unique certificate hierarchy."
        ),
        "references": [
            "CWE-321: Use of Hard-coded Cryptographic Key",
            "NIST SP 800-57 — Key Management",
        ],
        "cvss": "9.1 (Critical)",
    },

    "Embedded private key (PEM)": {
        "description": (
            "A PEM-encoded private key block (-----BEGIN ... PRIVATE KEY-----) was found "
            "directly embedded in the firmware binary. This is a critical finding — the full "
            "private key material is present and can be trivially extracted with any text editor."
        ),
        "impact": (
            "Complete compromise of any cryptographic operation using this key: TLS sessions "
            "can be decrypted, firmware updates can be forged, device identity can be "
            "impersonated. If the same key is used across a product line, all units are affected."
        ),
        "remediation": (
            "• Immediately revoke the certificate associated with this key.\n"
            "• Generate new device-unique key pairs in hardware (TPM/HSM).\n"
            "• Conduct a full security audit of the firmware signing and TLS infrastructure.\n"
            "• Consider whether devices in the field need emergency patching."
        ),
        "references": [
            "CWE-321: Use of Hard-coded Cryptographic Key",
            "CVE-2012-2980 — Samsung Galaxy private key exposure (real-world example)",
            "NIST SP 800-175B — Guideline for Using Cryptographic Standards",
        ],
        "cvss": "9.8 (Critical)",
    },

    "Default password": {
        "description": (
            "A 'default_password' or similar field was found with a value. Default credentials "
            "are frequently the same across an entire product line and are publicly catalogued "
            "in databases such as routerpasswords.com and DefaultCreds-cheat-sheet."
        ),
        "impact": (
            "Attackers use automated scanners to find devices with default credentials. "
            "This is the primary mechanism used by botnets like Mirai to recruit IoT devices. "
            "Full administrative access is typically achieved within seconds."
        ),
        "remediation": (
            "• Assign unique, random credentials per device at manufacturing time.\n"
            "• Force a credential change on first boot before allowing normal operation.\n"
            "• Implement lockout policies after failed authentication attempts."
        ),
        "references": [
            "CWE-1188: Insecure Default Initialization of Resource",
            "OWASP Firmware Top 10 — I1",
            "CVE-2016-1000 series (Mirai default credential exploitation)",
        ],
        "cvss": "9.8 (Critical)",
    },

    # ── Default / Bad credentials ─────────────────────────────────────────────
    "Default admin:admin credential": {
        "description": (
            "The string 'admin:admin' was found in the firmware, indicating a hardcoded or "
            "default username/password pair. This is one of the most commonly exploited "
            "credential pairs in embedded device attacks."
        ),
        "impact": (
            "Trivial authentication bypass. Automated attack tools explicitly try admin:admin "
            "against all exposed services. Full device takeover is achievable in under one second."
        ),
        "remediation": (
            "• Remove the hardcoded credential.\n"
            "• Generate unique credentials per device.\n"
            "• Force password change on first login."
        ),
        "references": [
            "CWE-798: Use of Hard-coded Credentials",
            "OWASP IoT Top 10 — I1",
        ],
        "cvss": "9.8 (Critical)",
    },

    "Default root:root credential": {
        "description": (
            "The string 'root:root' was found in the firmware. This represents a hardcoded "
            "root-level credential granting full superuser access to the device."
        ),
        "impact": (
            "An attacker gaining root access has complete control over the device: they can "
            "install malware, pivot to the network, exfiltrate data, brick the device, or "
            "enlist it in a botnet. Root-level compromise is the worst-case outcome."
        ),
        "remediation": (
            "• Remove all hardcoded root credentials immediately.\n"
            "• Disable root login over network services (SSH, Telnet).\n"
            "• Implement principle of least privilege for all system accounts."
        ),
        "references": [
            "CWE-798: Use of Hard-coded Credentials",
            "CVE-2016-1000045 — Root credential exposure in IoT firmware",
        ],
        "cvss": "9.8 (Critical)",
    },

    "Default guest:guest credential": {
        "description": (
            "A hardcoded guest:guest credential pair was found. Even 'guest' accounts can "
            "provide a foothold for privilege escalation or network reconnaissance."
        ),
        "impact": (
            "Provides initial access to the device. Combined with local privilege escalation "
            "vulnerabilities, this can lead to full compromise."
        ),
        "remediation": (
            "• Disable guest accounts or require unique generated credentials.\n"
            "• Apply strict access controls to any guest-level functionality."
        ),
        "references": ["CWE-798: Use of Hard-coded Credentials"],
        "cvss": "7.3 (High)",
    },

    "Default user:user credential": {
        "description": "A hardcoded user:user credential pair was found in the firmware.",
        "impact": "Provides authenticated access to the device with minimal effort.",
        "remediation": "Remove hardcoded credentials and replace with per-device generated credentials.",
        "references": ["CWE-798: Use of Hard-coded Credentials"],
        "cvss": "7.3 (High)",
    },

    "Common/default password string": {
        "description": (
            "A commonly known weak or default password string (e.g. '1234', 'password1', "
            "'letmein', 'qwerty', 'admin123') was found in the firmware."
        ),
        "impact": (
            "Common passwords are trivially cracked by dictionary attacks and are explicitly "
            "tried by all automated exploitation tools. They provide minimal protection."
        ),
        "remediation": (
            "• Use cryptographically random passwords of at least 16 characters.\n"
            "• Enforce password complexity requirements.\n"
            "• Consider passphrase-based approaches for human-entered credentials."
        ),
        "references": [
            "CWE-521: Weak Password Requirements",
            "NIST SP 800-63B — Digital Identity Guidelines",
        ],
        "cvss": "8.1 (High)",
    },

    # ── Weak cryptography ─────────────────────────────────────────────────────
    "MD5 usage (weak hash)": {
        "description": (
            "MD5 (Message Digest 5) was referenced in the firmware. MD5 was deprecated as a "
            "cryptographic hash function over a decade ago. Collision attacks against MD5 have "
            "been practically demonstrated since 2004 (Wang et al.)."
        ),
        "impact": (
            "An attacker can create two different inputs with the same MD5 hash, enabling "
            "file substitution attacks, certificate forgery, and bypassing integrity checks. "
            "MD5-hashed passwords can be cracked using precomputed rainbow tables in seconds."
        ),
        "remediation": (
            "• Replace MD5 with SHA-256 or SHA-3 for all security-relevant uses.\n"
            "• For password storage, use bcrypt, scrypt, or Argon2.\n"
            "• MD5 may be acceptable for non-security checksums (e.g. file deduplication) only."
        ),
        "references": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "RFC 6151 — Updated Security Considerations for MD5",
            "NIST SP 800-131A — Transitioning the Use of Cryptographic Algorithms",
        ],
        "cvss": "7.5 (High) in security-critical contexts",
    },

    "SHA-1 usage (weak hash)": {
        "description": (
            "SHA-1 was referenced in the firmware. SHA-1 was formally deprecated by NIST in "
            "2011. The first practical SHA-1 collision was demonstrated by Google's SHAttered "
            "attack in 2017, and chosen-prefix collisions were demonstrated in 2020."
        ),
        "impact": (
            "SHA-1 certificate or signature forgery is now within the budget of nation-state "
            "and well-funded criminal actors. SHA-1 TLS certificates have been removed from "
            "all major browsers. SHA-1 code signatures may be bypassed."
        ),
        "remediation": (
            "• Migrate all SHA-1 usage to SHA-256 or SHA-3.\n"
            "• Replace any SHA-1 TLS certificates immediately.\n"
            "• Update code signing infrastructure to use SHA-256 or better."
        ),
        "references": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "RFC 8996 — Deprecating TLS 1.0 and 1.1 (also deprecates SHA-1 PRF)",
            "NIST SP 800-131A Rev 2",
        ],
        "cvss": "6.5 (Medium) to 8.1 (High) depending on usage",
    },

    "DES usage (broken cipher)": {
        "description": (
            "DES (Data Encryption Standard) was referenced. DES uses a 56-bit key, which "
            "was broken by brute force in 1997 (DES Cracker project, 22 hours). It is "
            "completely unsuitable for any modern security application."
        ),
        "impact": (
            "Any data encrypted with DES can be decrypted by an attacker with modest "
            "computing resources. DES provides essentially no confidentiality protection "
            "by modern standards."
        ),
        "remediation": (
            "• Replace DES with AES-256-GCM or ChaCha20-Poly1305.\n"
            "• Ensure all encrypted storage and communications use modern ciphers.\n"
            "• Re-encrypt any data previously protected with DES."
        ),
        "references": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "NIST SP 800-131A — DES retired as of 2023",
        ],
        "cvss": "7.5 (High)",
    },

    "3DES usage (weak cipher)": {
        "description": (
            "Triple DES (3DES / TDEA) was referenced. While stronger than DES, 3DES was "
            "deprecated by NIST in 2017 (SP 800-131A) and is disallowed after 2023. "
            "It is vulnerable to the SWEET32 birthday attack in long-running sessions."
        ),
        "impact": (
            "SWEET32 attack allows recovery of plaintext from long TLS sessions using 3DES. "
            "3DES is also significantly slower than AES, creating performance issues."
        ),
        "remediation": "Replace 3DES with AES-256-GCM or ChaCha20-Poly1305 in all contexts.",
        "references": [
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
            "CVE-2016-2183 — SWEET32 Attack",
            "NIST SP 800-131A Rev 2",
        ],
        "cvss": "5.9 (Medium)",
    },

    "RC4 usage (broken cipher)": {
        "description": (
            "RC4 (Rivest Cipher 4) was referenced. RC4 has multiple well-known biases in "
            "its keystream and has been prohibited in TLS since RFC 7465 (2015). "
            "RC4 is trivially broken in WEP and weak in all contexts."
        ),
        "impact": (
            "RC4-encrypted traffic can be decrypted by passive attackers with sufficient "
            "ciphertext. In TLS, RC4 allows session cookie recovery (BEAST, RC4 NOMORE attacks)."
        ),
        "remediation": "Remove all RC4 cipher suite usage. Replace with AES-GCM or ChaCha20-Poly1305.",
        "references": [
            "RFC 7465 — Prohibiting RC4 Cipher Suites",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        ],
        "cvss": "7.5 (High)",
    },

    "OpenSSL weak API call": {
        "description": (
            "A direct call to a deprecated OpenSSL API using MD5, SHA-1, or DES was found "
            "(e.g. EVP_md5(), EVP_sha1(), EVP_des_cbc()). These APIs use known-weak algorithms."
        ),
        "impact": "Same as the underlying weak algorithm — enables hash collision or decryption attacks.",
        "remediation": (
            "• Replace EVP_md5() with EVP_sha256() or EVP_sha3_256().\n"
            "• Replace EVP_des_*() with EVP_aes_256_gcm().\n"
            "• Use OpenSSL 3.x with the legacy provider disabled."
        ),
        "references": [
            "OpenSSL 3.0 Migration Guide",
            "CWE-327: Use of a Broken or Risky Cryptographic Algorithm",
        ],
        "cvss": "6.5 (Medium)",
    },

    "crypt() — potentially weak hash": {
        "description": (
            "The crypt() function was referenced. Depending on the prefix used, crypt() may "
            "produce MD5 ($1$), SHA-256 ($5$), or DES-based hashes. The DES-based variant "
            "is critically weak with only 256 possible salts and a truncated 8-character key."
        ),
        "impact": "If DES-crypt is used, password hashes can be cracked in seconds with modern hardware.",
        "remediation": (
            "• If using crypt(), ensure $6$ (SHA-512) prefix.\n"
            "• Prefer libsodium's crypto_pwhash (Argon2) or bcrypt over crypt()."
        ),
        "references": ["CWE-916: Use of Password Hash With Insufficient Computational Effort"],
        "cvss": "5.9 (Medium) to 8.1 (High)",
    },

    "Deprecated SSL/TLS version": {
        "description": (
            "A reference to SSLv2, SSLv3, TLS 1.0, or TLS 1.1 was found. All of these "
            "protocol versions have been deprecated due to fundamental design weaknesses: "
            "POODLE (SSLv3), BEAST (TLS 1.0), CRIME, DROWN, and others."
        ),
        "impact": (
            "Downgrade attacks can force clients to negotiate these older protocols, enabling "
            "decryption of traffic. Many compliance frameworks (PCI DSS, NIST) explicitly "
            "prohibit TLS 1.0 and 1.1."
        ),
        "remediation": (
            "• Configure all TLS endpoints to accept only TLS 1.2 and TLS 1.3.\n"
            "• Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 in all OpenSSL/mbedTLS configs.\n"
            "• Test with SSLScan or Nessus to verify disabled protocols."
        ),
        "references": [
            "RFC 8996 — Deprecating TLS 1.0 and 1.1",
            "CVE-2014-3566 — POODLE (SSLv3)",
            "CWE-326: Inadequate Encryption Strength",
        ],
        "cvss": "5.9 (Medium)",
    },

    # ── Network / Services ────────────────────────────────────────────────────
    "Bind-all listener (0.0.0.0)": {
        "description": (
            "The address 0.0.0.0 was found, indicating a service may be configured to listen "
            "on all network interfaces. This means any network interface — including "
            "externally reachable ones — will have this service exposed."
        ),
        "impact": (
            "Services intended for internal use only (e.g. management interfaces, debug APIs) "
            "become reachable from external networks. Combined with any authentication weakness, "
            "this dramatically expands the attack surface."
        ),
        "remediation": (
            "• Bind management interfaces to 127.0.0.1 or a specific management interface IP.\n"
            "• Use firewall rules to restrict access to sensitive ports.\n"
            "• Audit all listening sockets using 'netstat -tlnp' on the device."
        ),
        "references": [
            "CWE-605: Multiple Binds to the Same Port",
            "OWASP Firmware Top 10 — I6: No Network Service Security",
        ],
        "cvss": "5.3 (Medium) — depends on service exposed",
    },

    "Telnet reference (unencrypted)": {
        "description": (
            "A Telnet reference was found in the firmware. Telnet transmits all data including "
            "credentials in cleartext with no encryption or integrity protection. It has been "
            "obsolete for secure remote access since SSH became available in 1995."
        ),
        "impact": (
            "Any passive observer on the network path (on the same LAN, rogue Wi-Fi AP, "
            "ISP-level interception) can capture all Telnet credentials and session content. "
            "Active attackers can perform man-in-the-middle to inject commands."
        ),
        "remediation": (
            "• Replace Telnet with SSH 2.0 (OpenSSH or Dropbear for embedded systems).\n"
            "• If Telnet must exist for legacy reasons, disable it by default and restrict "
            "access via firewall to trusted management networks only.\n"
            "• Consider removing the Telnet daemon binary entirely from the firmware."
        ),
        "references": [
            "CWE-319: Cleartext Transmission of Sensitive Information",
            "OWASP Firmware Top 10 — I3: Insecure Ecosystem Interfaces",
        ],
        "cvss": "7.5 (High)",
    },

    "FTP reference (unencrypted)": {
        "description": (
            "FTP (File Transfer Protocol) was referenced in the firmware. Like Telnet, FTP "
            "transmits credentials and data in cleartext. It also has inherent vulnerabilities "
            "such as PORT bounce attacks and passive mode firewall traversal issues."
        ),
        "impact": (
            "Credentials and file contents can be captured by passive sniffing. "
            "Active FTP allows attackers to abuse the device as a proxy to reach other hosts "
            "(FTP bounce attack)."
        ),
        "remediation": (
            "• Replace FTP with SFTP (SSH File Transfer Protocol) or SCP.\n"
            "• If a web-based file transfer is needed, use HTTPS.\n"
            "• Disable FTP if not operationally required."
        ),
        "references": [
            "CWE-319: Cleartext Transmission of Sensitive Information",
            "RFC 2577 — FTP Security Considerations",
        ],
        "cvss": "7.5 (High)",
    },

    "Plaintext HTTP URL": {
        "description": (
            "One or more HTTP:// URLs (not HTTPS) were found embedded in the firmware. "
            "These may be used for firmware update servers, telemetry endpoints, API calls, "
            "or configuration downloads — all transmitted without encryption."
        ),
        "impact": (
            "A network-level attacker can intercept and modify firmware updates (delivering "
            "malicious firmware), inject malicious responses into API calls, or capture "
            "sensitive telemetry data. This is the primary vector for 'evil twin' Wi-Fi attacks."
        ),
        "remediation": (
            "• Replace all HTTP:// URLs with HTTPS:// equivalents.\n"
            "• Implement certificate pinning for critical update and API endpoints.\n"
            "• Validate firmware update signatures independently of the transport layer.\n"
            "• Use HTTP Strict Transport Security (HSTS) if device hosts a web interface."
        ),
        "references": [
            "CWE-319: Cleartext Transmission of Sensitive Information",
            "CWE-295: Improper Certificate Validation",
            "OWASP — Transport Layer Security Cheat Sheet",
        ],
        "cvss": "6.8 (Medium) to 8.1 (High) for update channels",
    },

    "Telnet/FTP port reference": {
        "description": (
            "Port numbers 21 (FTP) or 23 (Telnet) were referenced in a context suggesting "
            "network service configuration. These ports indicate use of unencrypted legacy protocols."
        ),
        "impact": "Enables passive credential capture and traffic interception.",
        "remediation": "Disable Telnet (port 23) and FTP (port 21). Use SSH (22) and SFTP instead.",
        "references": ["CWE-319: Cleartext Transmission of Sensitive Information"],
        "cvss": "6.5 (Medium)",
    },

    "Backdoor string detected": {
        "description": (
            "The string 'backdoor' was found in the firmware binary or configuration. "
            "While this may occasionally appear in legitimate comments or documentation, "
            "in firmware it is a significant indicator requiring immediate investigation."
        ),
        "impact": (
            "If an actual backdoor is present, an attacker with knowledge of its trigger "
            "(special URL, magic packet, hardcoded password) can bypass all authentication "
            "and gain full device control. Vendor-installed backdoors have been found in "
            "numerous commercial routers and IoT devices."
        ),
        "remediation": (
            "• Reverse engineer the binary around this string to determine if a backdoor exists.\n"
            "• Use dynamic analysis (QEMU emulation, fuzzing) to test for hidden access paths.\n"
            "• Report to the device vendor if confirmed."
        ),
        "references": [
            "CWE-912: Hidden Functionality",
            "CVE-2014-100005 — D-Link router backdoor",
            "CVE-2021-20090 — Multiple router backdoor vulnerability",
        ],
        "cvss": "9.8 (Critical) if confirmed",
    },

    "SSH daemon reference": {
        "description": (
            "A reference to an SSH daemon (OpenSSH, Dropbear, sshd) was found. SSH is "
            "generally secure but requires careful configuration — weak key algorithms, "
            "root login, password authentication, and outdated versions introduce risk."
        ),
        "impact": (
            "A misconfigured SSH daemon may allow root login with password, accept deprecated "
            "key exchange algorithms (diffie-hellman-group1-sha1), or be running a version "
            "with known CVEs. Combined with weak/default credentials, SSH is a primary "
            "remote access vector."
        ),
        "remediation": (
            "• Disable root login via SSH (PermitRootLogin no).\n"
            "• Disable password authentication — use public key only.\n"
            "• Restrict SSH access to specific source IPs.\n"
            "• Keep SSH daemon updated to latest version.\n"
            "• Disable weak key exchange algorithms and ciphers."
        ),
        "references": [
            "CWE-285: Improper Authorization",
            "NIST SP 800-53 — SC-8 Transmission Confidentiality and Integrity",
        ],
        "cvss": "Context-dependent — 5.0–9.8",
    },

    "Netcat shell/listener": {
        "description": (
            "A pattern matching netcat with shell binding (-e /bin/sh or -l flag) was found. "
            "This is the classic pattern for establishing a reverse or bind shell — "
            "a technique almost exclusively used for malicious purposes in firmware."
        ),
        "impact": (
            "If active, this provides an unauthenticated shell listener on a network port, "
            "granting any connecting party full command execution on the device. "
            "This is textbook backdoor behaviour."
        ),
        "remediation": (
            "• Investigate this finding immediately — reverse engineer the context.\n"
            "• Remove netcat from the firmware image if not operationally justified.\n"
            "• If netcat is required, strip the -e option (use OpenBSD netcat without shell support)."
        ),
        "references": [
            "CWE-912: Hidden Functionality",
            "CWE-78: Improper Neutralization of Special Elements (OS Command Injection)",
        ],
        "cvss": "9.8 (Critical)",
    },

    # ── Binary hardening ──────────────────────────────────────────────────────
    "No stack canary detected": {
        "description": (
            "The binary does not appear to use stack canaries (stack smash protection). "
            "Stack canaries are values placed between local variables and the return address "
            "that detect stack buffer overflow attempts before a function returns. "
            "They are enabled with -fstack-protector-strong at compile time."
        ),
        "impact": (
            "Stack buffer overflows — one of the most common vulnerability classes — can "
            "directly overwrite the return address and redirect code execution. "
            "Without canaries, these attacks succeed reliably and require no information leak."
        ),
        "remediation": (
            "• Recompile all binaries with -fstack-protector-strong (GCC/Clang).\n"
            "• Prefer -fstack-protector-all for maximum coverage.\n"
            "• Additionally enable FORTIFY_SOURCE=2 and ASLR."
        ),
        "references": [
            "CWE-121: Stack-based Buffer Overflow",
            "CWE-693: Protection Mechanism Failure",
            "GCC manual — -fstack-protector",
        ],
        "cvss": "Amplifies other vulnerabilities — enables reliable exploitation",
    },

    "Stack canary": {
        "description": "The binary uses stack smash protection (__stack_chk_fail). This is a positive security control.",
        "impact": "Reduces exploitability of stack buffer overflows by detecting overwrite before return.",
        "remediation": "No action needed. Continue using -fstack-protector-strong in build pipeline.",
        "references": ["CWE-121: Stack-based Buffer Overflow"],
        "cvss": "N/A — Positive finding",
    },

    "FORTIFY_SOURCE": {
        "description": "FORTIFY_SOURCE hardening is present. This replaces unsafe libc functions with bounds-checked variants.",
        "impact": "Reduces the exploitability of buffer overflows in common string/memory operations.",
        "remediation": "No action needed. Ensure -D_FORTIFY_SOURCE=2 is set in all build configurations.",
        "references": ["CWE-120: Buffer Copy without Checking Size of Input"],
        "cvss": "N/A — Positive finding",
    },

    "PIE (Position Independent Executable) enabled": {
        "description": "The binary is compiled as a Position Independent Executable, enabling ASLR to randomize its load address.",
        "impact": "Makes return-oriented programming (ROP) attacks significantly harder as base address is unknown.",
        "remediation": "No action needed. Maintain -fPIE -pie in build flags.",
        "references": ["CWE-693: Protection Mechanism Failure"],
        "cvss": "N/A — Positive finding",
    },

    "Non-PIE executable (fixed base address)": {
        "description": (
            "The ELF binary is compiled as ET_EXEC (non-PIE), meaning it loads at a fixed, "
            "predictable virtual address. This prevents ASLR from randomising the binary's "
            "own code and data segments."
        ),
        "impact": (
            "An attacker exploiting a memory corruption vulnerability can predict the exact "
            "addresses of gadgets, functions, and data — making ROP chain construction "
            "straightforward without needing an information leak."
        ),
        "remediation": (
            "• Recompile with -fPIE -pie flags.\n"
            "• Ensure the kernel has ASLR enabled (echo 2 > /proc/sys/kernel/randomize_va_space).\n"
            "• Test with checksec.sh to verify PIE status post-build."
        ),
        "references": [
            "CWE-693: Protection Mechanism Failure",
            "checksec — https://github.com/slimm609/checksec.sh",
        ],
        "cvss": "Amplifies exploitability of memory corruption vulnerabilities",
    },

    "Unsafe C functions found in binary": {
        "description": (
            "One or more unsafe C standard library functions were found in the binary: "
            "strcpy, strcat, sprintf, gets, scanf, system, popen, execve, memcpy, etc. "
            "These functions do not perform bounds checking and are the root cause of "
            "the majority of historical buffer overflow vulnerabilities."
        ),
        "impact": (
            "If any of these functions process attacker-controlled input without proper "
            "length validation, a buffer overflow or command injection vulnerability exists. "
            "gets() in particular has no safe usage — it cannot be called safely."
        ),
        "remediation": (
            "• Replace strcpy → strncpy/strlcpy, strcat → strncat/strlcat.\n"
            "• Replace sprintf → snprintf with explicit size.\n"
            "• Replace gets() — there is no safe replacement; use fgets() instead.\n"
            "• Replace system()/popen() with execve() with explicit argument arrays.\n"
            "• Enable FORTIFY_SOURCE=2 to catch some misuses at compile time."
        ),
        "references": [
            "CWE-120: Buffer Copy without Checking Size of Input (Classic Buffer Overflow)",
            "CWE-78: OS Command Injection (system, popen)",
            "CWE-676: Use of Potentially Dangerous Function",
            "OWASP — Buffer Overflow",
        ],
        "cvss": "7.8 (High) if exploitable path exists",
    },

    "RPATH / /tmp reference in binary": {
        "description": (
            "The binary contains an RPATH or RUNPATH entry referencing /tmp or another "
            "attacker-writable directory. When the dynamic linker resolves shared libraries, "
            "it searches RPATH locations first."
        ),
        "impact": (
            "An attacker with write access to /tmp can place a malicious shared library "
            "there, which will be loaded instead of the legitimate library when the binary "
            "runs — a dynamic linker hijacking / DLL planting attack."
        ),
        "remediation": (
            "• Remove any RPATH/RUNPATH entries pointing to /tmp or world-writable directories.\n"
            "• Use absolute paths to system library directories only.\n"
            "• Set the sticky bit on /tmp and use namespacing to isolate processes."
        ),
        "references": [
            "CWE-427: Uncontrolled Search Path Element",
            "CVE-2019-13915 — RPATH hijacking example",
        ],
        "cvss": "7.0 (High)",
    },

    # ── File permissions ──────────────────────────────────────────────────────
    "World-writable files found": {
        "description": (
            "One or more files in the firmware filesystem have world-writable permissions "
            "(mode includes o+w). Any unprivileged process or user can modify these files."
        ),
        "impact": (
            "Attackers with any level of access to the device can modify world-writable "
            "files. If these are executables, configuration files, or scripts run by "
            "privileged processes, this enables privilege escalation."
        ),
        "remediation": (
            "• Audit and correct file permissions: chmod o-w <file>.\n"
            "• Run 'find / -perm -002 -type f' on the device to enumerate all world-writable files.\n"
            "• Mount filesystems with noexec and nosuid where appropriate."
        ),
        "references": [
            "CWE-732: Incorrect Permission Assignment for Critical Resource",
            "CIS Benchmark — file permission hardening",
        ],
        "cvss": "6.5–7.8 depending on file type",
    },

    "SUID/SGID files found": {
        "description": (
            "Files with SUID (Set User ID) or SGID (Set Group ID) bits were found. When "
            "executed, SUID files run with the owner's privileges (often root) rather than "
            "the caller's. A vulnerable SUID binary is a direct privilege escalation path."
        ),
        "impact": (
            "A buffer overflow, command injection, or path traversal vulnerability in a SUID "
            "binary results in immediate privilege escalation to root. Linux privilege "
            "escalation CTFs and real-world attacks frequently target misconfigured SUID binaries."
        ),
        "remediation": (
            "• Review the necessity of SUID/SGID on every identified file.\n"
            "• Remove SUID from binaries that don't require it: chmod u-s <file>.\n"
            "• Use Linux capabilities (setcap) instead of SUID where possible.\n"
            "• Mount filesystems with nosuid option.\n"
            "• Keep SUID binaries updated to patch known vulnerabilities."
        ),
        "references": [
            "CWE-269: Improper Privilege Management",
            "CWE-732: Incorrect Permission Assignment for Critical Resource",
            "GTFOBins — https://gtfobins.github.io/ (SUID exploitation reference)",
        ],
        "cvss": "7.8 (High) — local privilege escalation",
    },

    "SUID/SGID permission set": {
        "description": "A chmod command in a script sets SUID or SGID bits on a file (e.g. chmod 4755).",
        "impact": "Creates SUID binaries at runtime, enabling potential privilege escalation as described above.",
        "remediation": "Remove unnecessary SUID/SGID permission assignments in scripts. Audit resulting file permissions.",
        "references": ["CWE-269: Improper Privilege Management"],
        "cvss": "7.0 (High)",
    },

    "Setuid bit applied": {
        "description": "A script applies the setuid bit via chmod +s. This has the same effect as SUID/SGID.",
        "impact": "Creates a SUID/SGID binary that runs with elevated privileges.",
        "remediation": "Audit whether the setuid bit is necessary. Use Linux capabilities as a least-privilege alternative.",
        "references": ["CWE-269: Improper Privilege Management"],
        "cvss": "7.0 (High)",
    },

    # ── Sensitive paths ───────────────────────────────────────────────────────
    "Reference to /etc/passwd": {
        "description": (
            "/etc/passwd was referenced in the firmware. This file contains user account "
            "information. On modern systems passwords are in /etc/shadow, but /etc/passwd "
            "still reveals usernames, UIDs, GIDs, home directories, and shell paths."
        ),
        "impact": (
            "Leaking /etc/passwd aids user enumeration and account profiling. "
            "On very old systems where passwords were stored in /etc/passwd, "
            "it enables direct password cracking."
        ),
        "remediation": (
            "• Ensure /etc/passwd is not served via any network interface.\n"
            "• Restrict read access to the minimum necessary.\n"
            "• Review why the firmware accesses /etc/passwd."
        ),
        "references": ["CWE-200: Exposure of Sensitive Information to an Unauthorized Actor"],
        "cvss": "4.0 (Medium) — informational exposure",
    },

    "Reference to /etc/shadow (password hashes)": {
        "description": (
            "/etc/shadow was referenced in the firmware. This file contains hashed passwords "
            "for all system accounts and is normally readable only by root. Any process "
            "referencing /etc/shadow that is not a PAM module or passwd utility is suspicious."
        ),
        "impact": (
            "If /etc/shadow contents are exposed (e.g. via path traversal or command injection), "
            "an attacker can conduct offline password cracking against all account hashes "
            "using tools like hashcat or John the Ripper."
        ),
        "remediation": (
            "• Restrict /etc/shadow permissions to 640 root:shadow.\n"
            "• Audit why this firmware component accesses /etc/shadow.\n"
            "• Use PAM for authentication rather than direct shadow file access."
        ),
        "references": [
            "CWE-256: Plaintext Storage of a Password",
            "CWE-916: Use of Password Hash With Insufficient Computational Effort",
        ],
        "cvss": "7.5 (High) if exposed",
    },

    "Reference to /etc/sudoers": {
        "description": (
            "/etc/sudoers was referenced in the firmware. This file controls which users can "
            "execute commands with elevated privileges via sudo. Modification of this file "
            "is a classic persistence and privilege escalation technique."
        ),
        "impact": (
            "If an attacker can write to /etc/sudoers (e.g. via a path traversal or "
            "misconfigured SUID binary), they can grant themselves unrestricted root access. "
            "Firmware that reads or modifies sudoers is a red flag."
        ),
        "remediation": (
            "• Ensure /etc/sudoers is read-only root:root (440).\n"
            "• Use sudoers.d drop-in directory with strict permissions.\n"
            "• Validate any sudoers modifications at boot against a known-good hash."
        ),
        "references": [
            "CWE-269: Improper Privilege Management",
            "CWE-732: Incorrect Permission Assignment for Critical Resource",
        ],
        "cvss": "7.8 (High)",
    },

    "Reference to /proc filesystem": {
        "description": (
            "The /proc virtual filesystem was referenced. /proc exposes kernel internals, "
            "process memory maps, network state, and system configuration. "
            "Some /proc paths allow writing to modify kernel parameters at runtime."
        ),
        "impact": (
            "Reading /proc/*/mem or /proc/*/maps can enable process memory inspection. "
            "Writing to /proc/sys/* can disable security features (e.g. disabling ASLR "
            "via /proc/sys/kernel/randomize_va_space)."
        ),
        "remediation": (
            "• Restrict access to /proc using mount namespaces.\n"
            "• Audit /proc writes — they should not modify security-relevant kernel parameters.\n"
            "• Use seccomp or AppArmor to limit /proc access."
        ),
        "references": ["CWE-200: Exposure of Sensitive Information"],
        "cvss": "4.0–7.5 depending on what is accessed",
    },

    "Reference to /dev/mem (direct memory access)": {
        "description": (
            "/dev/mem provides direct access to physical memory. Access to /dev/mem allows "
            "reading and writing arbitrary physical memory addresses, bypassing all OS-level "
            "memory protection. It is restricted (or blocked entirely) on hardened systems."
        ),
        "impact": (
            "An attacker with /dev/mem access can read kernel memory (extracting keys, "
            "credentials, and session tokens), modify running kernel code, bypass security "
            "checks, or install kernel-level malware without a kernel vulnerability."
        ),
        "remediation": (
            "• Block access to /dev/mem by setting CONFIG_STRICT_DEVMEM=y in the kernel.\n"
            "• Enable CONFIG_IO_STRICT_DEVMEM=y for additional restrictions.\n"
            "• Remove /dev/mem from the device filesystem if not required."
        ),
        "references": [
            "CWE-284: Improper Access Control",
            "Linux kernel — CONFIG_STRICT_DEVMEM",
        ],
        "cvss": "8.4 (High) — physical memory access",
    },

    "Reference to SSL private key directory": {
        "description": (
            "A reference to /etc/ssl/private was found. This directory traditionally "
            "stores TLS private keys and should be accessible only to root and the ssl-cert group."
        ),
        "impact": "If private keys in this directory are exposed, TLS can be broken and traffic decrypted.",
        "remediation": (
            "• Ensure /etc/ssl/private has mode 710 root:ssl-cert.\n"
            "• Audit firmware components that reference this directory.\n"
            "• Consider hardware-backed key storage to avoid file-based private keys."
        ),
        "references": [
            "CWE-321: Use of Hard-coded Cryptographic Key",
            "CWE-732: Incorrect Permission Assignment for Critical Resource",
        ],
        "cvss": "7.5 (High)",
    },

    # ── Config findings ───────────────────────────────────────────────────────
    "Credential found in config file": {
        "description": "A password or secret field with a value was found in a configuration file within the firmware.",
        "impact": "Config files are often world-readable. Credentials stored here can be read by any process or user with filesystem access.",
        "remediation": (
            "• Store credentials in encrypted storage, not config files.\n"
            "• Use environment variable injection or a secrets manager.\n"
            "• If config files must reference credentials, restrict file permissions to 600."
        ),
        "references": ["CWE-312: Cleartext Storage of Sensitive Information"],
        "cvss": "7.5 (High)",
    },

    "Debug mode enabled in config": {
        "description": "A configuration file has debug mode enabled (debug=true/1/yes/on).",
        "impact": (
            "Debug mode typically enables verbose logging (leaking internal state, credentials, "
            "and memory addresses), disables certain security checks, and may expose debug "
            "API endpoints or interfaces not intended for production use."
        ),
        "remediation": "Ensure debug mode is disabled in all production firmware builds. Use build-time flags to strip debug code.",
        "references": ["CWE-215: Insertion of Sensitive Information Into Log File"],
        "cvss": "4.3 (Medium)",
    },

    "TLS certificate verification disabled": {
        "description": (
            "A configuration file disables TLS/SSL certificate verification "
            "(verify_ssl=false, ssl_verify=0, etc.). This means the firmware will accept "
            "any TLS certificate including self-signed and expired ones."
        ),
        "impact": (
            "All TLS connections from this device are vulnerable to man-in-the-middle attacks. "
            "An attacker on the network path can intercept and modify any HTTPS traffic "
            "— including firmware updates, API calls, and telemetry — without detection."
        ),
        "remediation": (
            "• Re-enable TLS certificate verification.\n"
            "• Implement certificate pinning for critical endpoints (update servers, cloud APIs).\n"
            "• If using self-signed certificates, bundle the CA certificate in the firmware "
            "and pin to it rather than disabling verification."
        ),
        "references": [
            "CWE-295: Improper Certificate Validation",
            "CWE-297: Improper Validation of Certificate with Host Mismatch",
            "OWASP — Transport Layer Security Cheat Sheet",
        ],
        "cvss": "7.4 (High)",
    },

    "Wildcard CORS policy configured": {
        "description": (
            "The firmware's web interface is configured with Access-Control-Allow-Origin: * "
            "(wildcard CORS). This allows any website to make cross-origin requests to the "
            "device's web interface from a victim's browser."
        ),
        "impact": (
            "A malicious website visited by someone on the same network as the device can "
            "make authenticated requests to the device's management interface, read responses, "
            "and perform actions as the logged-in user — a CSRF-like attack without requiring "
            "state forgery."
        ),
        "remediation": (
            "• Restrict CORS to specific trusted origins.\n"
            "• Require CSRF tokens for all state-changing requests.\n"
            "• Do not combine wildcard CORS with credentials (withCredentials: true)."
        ),
        "references": [
            "CWE-942: Permissive Cross-domain Policy",
            "OWASP — CORS Security Cheat Sheet",
        ],
        "cvss": "6.5 (Medium)",
    },

    # ── Script findings ───────────────────────────────────────────────────────
    "eval() usage in script": {
        "description": (
            "The eval() function was found in a script. eval() executes a string as code "
            "at runtime. If any part of the evaluated string can be influenced by user input "
            "or external data, this is a code injection vulnerability."
        ),
        "impact": "Arbitrary code execution in the context of the script — potentially root if the script runs as root.",
        "remediation": (
            "• Avoid eval() entirely. Refactor to use explicit function calls or data structures.\n"
            "• If eval() is unavoidable, strictly validate and whitelist all input before passing it."
        ),
        "references": [
            "CWE-95: Improper Neutralization of Directives in Dynamically Evaluated Code",
            "CWE-78: OS Command Injection",
        ],
        "cvss": "8.8 (High) if input is attacker-controlled",
    },

    "curl/wget piped to shell": {
        "description": (
            "The pattern 'curl ... | bash' or 'wget ... | sh' was found in a script. "
            "This downloads content from a URL and immediately executes it in a shell "
            "without any verification."
        ),
        "impact": (
            "If an attacker can intercept or control the URL (via DNS hijacking, HTTP "
            "MITM, or compromise of the hosting server), they can execute arbitrary code "
            "on the device with the script's privilege level. This is a trivial supply-chain "
            "attack vector."
        ),
        "remediation": (
            "• Download to a file, verify a cryptographic signature or hash, then execute.\n"
            "• Use HTTPS for downloads.\n"
            "• Pin the server certificate.\n"
            "• Sign all scripts and verify signatures before execution."
        ),
        "references": [
            "CWE-494: Download of Code Without Integrity Check",
            "CWE-829: Inclusion of Functionality from Untrusted Control Sphere",
        ],
        "cvss": "8.1 (High)",
    },

    "Destructive rm -rf / command found": {
        "description": (
            "'rm -rf /' or a similar destructive recursive delete from the root was found "
            "in a script. This command deletes all files on the system."
        ),
        "impact": (
            "If triggered (accidentally or by an attacker), this causes complete data destruction "
            "and device bricking. In attack contexts, this is used as a kill switch or destructive payload."
        ),
        "remediation": (
            "• Remove this command entirely if not intentionally required.\n"
            "• If a factory reset wipe is intended, scope it to specific directories and "
            "add confirmation gates.\n"
            "• Use --preserve-root flag at minimum."
        ),
        "references": [
            "CWE-73: External Control of File Name or Path",
            "CWE-400: Uncontrolled Resource Consumption",
        ],
        "cvss": "9.1 (Critical) — availability destruction",
    },

    "Hardcoded public IP addresses": {
        "description": (
            "Public IP addresses were found hardcoded in the firmware. These may be update "
            "servers, telemetry endpoints, NTP servers, or C2 (command-and-control) addresses."
        ),
        "impact": (
            "Hardcoded IPs bypass DNS-based domain takedown mechanisms used to disrupt "
            "botnets and malware C2 infrastructure. If these IPs are update servers, "
            "device availability depends on the reachability of specific infrastructure. "
            "If IPs belong to third parties, this may indicate supply-chain compromise."
        ),
        "remediation": (
            "• Use domain names instead of hardcoded IPs to allow infrastructure flexibility.\n"
            "• If IPs must be hardcoded, document and justify each one.\n"
            "• Verify that all hardcoded IPs belong to expected infrastructure."
        ),
        "references": [
            "CWE-770: Allocation of Resources Without Limits or Throttling",
            "OWASP Firmware Top 10 — I7",
        ],
        "cvss": "4.0 (Medium) — depends on purpose",
    },

    # ── Known signatures ──────────────────────────────────────────────────────
    "Log4j library reference — check for CVE-2021-44228": {
        "description": (
            "A reference to log4j was found. Apache Log4j 2.x versions prior to 2.17.1 "
            "are vulnerable to CVE-2021-44228 (Log4Shell), rated 10.0 Critical. "
            "This allows unauthenticated remote code execution via JNDI injection in log messages."
        ),
        "impact": (
            "Remote unauthenticated code execution. Any log message containing attacker-controlled "
            "input (e.g. usernames, HTTP headers, User-Agent strings) can trigger an outbound "
            "LDAP/RMI connection that loads and executes attacker-controlled Java classes."
        ),
        "remediation": (
            "• Upgrade Log4j 2.x to version 2.17.1 or later (2.12.4 for Java 7, 2.3.2 for Java 6).\n"
            "• Set log4j2.formatMsgNoLookups=true as a temporary mitigation.\n"
            "• Remove JndiLookup class from the classpath as emergency mitigation."
        ),
        "references": [
            "CVE-2021-44228 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2021-44228",
            "Apache Log4j Security Page — https://logging.apache.org/log4j/2.x/security.html",
            "CISA Log4Shell advisory",
        ],
        "cvss": "10.0 (Critical) — CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
    },

    "OpenSSL 1.0.x linked — known vulnerable versions": {
        "description": (
            "The firmware links against OpenSSL 1.0.x (libssl.so.1.0 or libcrypto.so.1.0). "
            "OpenSSL 1.0.x reached end-of-life on 31 December 2019 and has received no security "
            "patches since then. Numerous unpatched CVEs exist."
        ),
        "impact": (
            "Devices running end-of-life OpenSSL are permanently vulnerable to all CVEs "
            "discovered after EOL, including potentially critical ones. Historical CVEs include "
            "Heartbleed (CVE-2014-0160), DROWN (CVE-2016-0800), and CCS Injection (CVE-2014-0224)."
        ),
        "remediation": (
            "• Upgrade to OpenSSL 3.x (LTS) or at minimum OpenSSL 1.1.1 (EOL 2023).\n"
            "• If upgrading is not possible, consider switching to mbedTLS or WolfSSL for "
            "embedded systems — both have smaller footprints and active security support.\n"
            "• Apply all available vendor security patches."
        ),
        "references": [
            "OpenSSL EOL Policy — https://www.openssl.org/policies/releasestrat.html",
            "CVE-2014-0160 (Heartbleed)",
            "CVE-2016-0800 (DROWN)",
        ],
        "cvss": "Multiple CVEs up to 10.0 (Critical)",
    },

    "uTelnetd (unsecured telnet daemon) found": {
        "description": (
            "utelnetd, a minimal telnet daemon common in embedded Linux firmware, was found. "
            "utelnetd provides unauthenticated or minimally-authenticated shell access via "
            "cleartext Telnet. It is frequently found in router and IoT firmware."
        ),
        "impact": (
            "Any network-reachable user can obtain a shell. Combined with weak or default "
            "credentials (which frequently accompany utelnetd in firmware), this is trivial "
            "full device compromise. utelnetd has been exploited extensively by Mirai and "
            "subsequent IoT botnets."
        ),
        "remediation": (
            "• Remove utelnetd from the firmware entirely.\n"
            "• If remote shell access is required, use Dropbear SSH with key-only authentication.\n"
            "• Block Telnet (port 23) at all network boundaries."
        ),
        "references": [
            "CVE-2016-1000 series (Mirai botnet — Telnet exploitation)",
            "CWE-319: Cleartext Transmission of Sensitive Information",
            "OWASP Firmware Top 10 — I3",
        ],
        "cvss": "9.8 (Critical)",
    },

    "BusyBox embedded — check version for known CVEs": {
        "description": (
            "BusyBox was found in the firmware. BusyBox is a common multi-call binary used "
            "in embedded Linux systems, combining many Unix utilities in a single executable. "
            "Older versions have known CVEs affecting specific applets."
        ),
        "impact": (
            "Depends on the BusyBox version and which applets are enabled. Vulnerable versions "
            "may allow privilege escalation or remote code execution through specific applets. "
            "The version should be identified and checked against the BusyBox CVE list."
        ),
        "remediation": (
            "• Identify the BusyBox version (busybox --help or strings output).\n"
            "• Check https://www.busybox.net/news.html for applicable CVEs.\n"
            "• Upgrade to the latest stable BusyBox version.\n"
            "• Disable unneeded applets at compile time to reduce attack surface."
        ),
        "references": [
            "BusyBox security advisories — https://busybox.net/news.html",
            "Mitre BusyBox CVEs — https://cve.mitre.org/cgi-bin/cvekey.cgi?keyword=busybox",
        ],
        "cvss": "Variable — check specific version",
    },

    "Shellshock reference found": {
        "description": (
            "A reference to 'shellshock' was found. Shellshock (CVE-2014-6271 and related) "
            "is a critical vulnerability in GNU Bash allowing arbitrary code execution via "
            "specially crafted environment variables. Bash versions prior to 4.3 patch 25 are affected."
        ),
        "impact": (
            "Remote code execution in any context where user input reaches Bash environment "
            "variables — CGI scripts, DHCP clients, SSH ForceCommand, and many others. "
            "Rated 10.0 Critical."
        ),
        "remediation": (
            "• Ensure Bash is updated to 4.3 patch 25+ or 4.4+.\n"
            "• Replace CGI-based web services with alternatives that do not invoke shell.\n"
            "• Use 'bash --restricted' or dash/ash in contexts where only simple scripts are needed."
        ),
        "references": [
            "CVE-2014-6271 — NVD: https://nvd.nist.gov/vuln/detail/CVE-2014-6271",
            "CVE-2014-7169, CVE-2014-7186, CVE-2014-7187 — related Shellshock variants",
        ],
        "cvss": "10.0 (Critical)",
    },

    # ── Entropy ───────────────────────────────────────────────────────────────
    "Very high entropy — file may be encrypted or packed": {
        "description": (
            "The firmware file has Shannon entropy above 7.5 (out of 8.0 maximum). "
            "This level of entropy is characteristic of encrypted or highly compressed data. "
            "It significantly impedes static security analysis as patterns and strings are obscured."
        ),
        "impact": (
            "Security analysis tools (including this one) cannot scan encrypted regions for "
            "credentials, vulnerabilities, or malicious code. If encryption is used to hide "
            "malicious functionality, it will not be detected by static analysis alone."
        ),
        "remediation": (
            "• Identify whether encryption or compression is expected for this firmware type.\n"
            "• Use dynamic analysis (QEMU emulation, hardware debugging) to analyse decrypted memory.\n"
            "• Request unencrypted firmware images from the vendor for security assessment.\n"
            "• Use firmware unpacking tools (binwalk, unblob) to identify and extract compressed regions."
        ),
        "references": [
            "binwalk — https://github.com/ReFirmLabs/binwalk",
            "unblob — https://github.com/onekey-sec/unblob",
            "CWE-311: Missing Encryption of Sensitive Data (if unencrypted storage is found alongside)",
        ],
        "cvss": "N/A — analysis limitation indicator",
    },

    # ── Structure ─────────────────────────────────────────────────────────────
    "High null-byte ratio — may be sparse/padded image": {
        "description": (
            "The firmware contains a high proportion of null (0x00) bytes. This is common "
            "in flash memory images where unused regions are filled with 0x00 or 0xFF, "
            "or in sparse filesystem images."
        ),
        "impact": (
            "Low direct security impact from the padding itself. However, sparse images may "
            "contain hidden data in unexpected regions, and analysis tools may miss content "
            "embedded within padding areas."
        ),
        "remediation": (
            "• Use binwalk or a hex editor to scan for content within null-filled regions.\n"
            "• Verify that the null regions are genuinely unused flash space.\n"
            "• Check for steganographic techniques hiding data in padding."
        ),
        "references": [],
        "cvss": "N/A — structural observation",
    },

    "Disk image with MBR detected": {
        "description": (
            "The firmware contains a Master Boot Record (MBR) signature. This indicates a "
            "raw disk or flash image that includes the bootloader sector. Bootkits can be "
            "embedded in the MBR/VBR and execute before the OS loads."
        ),
        "impact": (
            "Bootkits are extremely persistent — they survive OS reinstallation, are invisible "
            "to OS-level security tools, and can compromise the entire trust chain from boot. "
            "Analysis of the MBR code is required to rule out malicious modification."
        ),
        "remediation": (
            "• Inspect the MBR code (first 446 bytes) for unexpected executable code.\n"
            "• Verify the bootloader against a known-good hash from the vendor.\n"
            "• Enable Secure Boot with signature verification of all boot stages."
        ),
        "references": [
            "CWE-494: Download of Code Without Integrity Check",
            "NIST SP 800-147 — BIOS Protection Guidelines",
        ],
        "cvss": "8.6 (High) if bootloader is compromised",
    },

    # ── Unresolved security issues ────────────────────────────────────────────
    "Unresolved security TODO": {
        "description": (
            "A TODO comment referencing security, authentication, or cryptography was found "
            "in the firmware. This indicates known, unresolved security work that was "
            "deferred during development."
        ),
        "impact": (
            "Unresolved security TODOs typically indicate incomplete security controls — "
            "missing authentication, placeholder implementations, or known vulnerabilities "
            "that were acknowledged but not addressed before shipping."
        ),
        "remediation": (
            "• Enumerate and prioritise all security-related TODOs.\n"
            "• Do not ship firmware with unresolved security TODOs.\n"
            "• Include TODO scanning in CI/CD security gates."
        ),
        "references": ["CWE-1164: Irrelevant Code (indirect — incomplete security implementation)"],
        "cvss": "Depends on what is deferred",
    },

    "Unresolved FIXME in security code": {
        "description": (
            "A FIXME comment in security-sensitive code (authentication, cryptography, "
            "access control) was found. FIXMEs typically indicate known bugs or incomplete "
            "implementations acknowledged by the developer."
        ),
        "impact": "Known bug in security code — the developer identified a problem that was never resolved.",
        "remediation": (
            "• Treat all security FIXMEs as mandatory before release.\n"
            "• Add automated checks that fail builds containing FIXME in security-critical modules."
        ),
        "references": ["CWE-693: Protection Mechanism Failure"],
        "cvss": "Depends on what is deferred",
    },
}


def get_knowledge(title: str) -> dict:
    """
    Look up rich information for a finding title.
    Falls back to a generic entry if the exact title is not found.
    Also tries partial / keyword matching.
    """
    # Exact match
    if title in KNOWLEDGE_BASE:
        return KNOWLEDGE_BASE[title]

    # Prefix / substring match
    title_lower = title.lower()
    for key, val in KNOWLEDGE_BASE.items():
        if key.lower() in title_lower or title_lower in key.lower():
            return val

    # Keyword fallback
    keywords = {
        "password": "Hardcoded password",
        "credential": "Default admin:admin credential",
        "private key": "Embedded private key (PEM)",
        "md5": "MD5 usage (weak hash)",
        "sha-1": "SHA-1 usage (weak hash)",
        "sha1": "SHA-1 usage (weak hash)",
        "des": "DES usage (broken cipher)",
        "rc4": "RC4 usage (broken cipher)",
        "telnet": "Telnet reference (unencrypted)",
        "ftp": "FTP reference (unencrypted)",
        "http://": "Plaintext HTTP URL",
        "stack canary": "No stack canary detected",
        "pie": "Non-PIE executable (fixed base address)",
        "strcpy": "Unsafe C functions found in binary",
        "suid": "SUID/SGID files found",
        "world-writable": "World-writable files found",
        "log4": "Log4j library reference — check for CVE-2021-44228",
        "openssl 1.0": "OpenSSL 1.0.x linked — known vulnerable versions",
        "busybox": "BusyBox embedded — check version for known CVEs",
        "shellshock": "Shellshock reference found",
        "entropy": "Very high entropy — file may be encrypted or packed",
        "backdoor": "Backdoor string detected",
        "tls": "Deprecated SSL/TLS version",
        "ssl": "Deprecated SSL/TLS version",
        "cors": "Wildcard CORS policy configured",
        "eval": "eval() usage in script",
        "curl": "curl/wget piped to shell",
    }
    for kw, kb_key in keywords.items():
        if kw in title_lower:
            return KNOWLEDGE_BASE.get(kb_key, _generic(title))

    return _generic(title)


def _generic(title: str) -> dict:
    return {
        "description": (
            f"A security finding of type '{title}' was detected in the firmware. "
            "Review the location and detail fields to understand the specific context."
        ),
        "impact": "Depends on context — review the finding detail and surrounding code.",
        "remediation": (
            "Investigate the flagged location, understand whether the finding represents "
            "a real vulnerability in this firmware's threat model, and apply appropriate "
            "mitigations based on the specific context."
        ),
        "references": [
            "OWASP Firmware Security Testing Methodology — https://github.com/scriptingxss/owasp-fstm",
            "ENISA — Good Practices for Security of IoT",
        ],
        "cvss": "Unknown — manual investigation required",
    }
