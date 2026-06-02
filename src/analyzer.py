"""
FirmwareGuard — Analysis Engine
Supports: ISO, BIN, ZIP, TAR, GZ, IMG, ROM, ELF, HEX, SREC, SQUASHFS, EXT*, and more
"""

import os
import re
import sys
import math
import struct
import hashlib
import zipfile
import tarfile
import gzip
import shutil
import tempfile
import mimetypes
import subprocess
from pathlib import Path
from datetime import datetime
from collections import defaultdict

# Imported lazily to avoid circular issues when run standalone
try:
    from knowledge import get_knowledge
except ImportError:
    def get_knowledge(title): return {}


# ---------------------------------------------------------------------------
#  Severity levels
# ---------------------------------------------------------------------------
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"
OK       = "OK"


# ---------------------------------------------------------------------------
#  Pattern libraries
# ---------------------------------------------------------------------------

# Credentials & secrets
CREDENTIAL_PATTERNS = [
    (re.compile(rb'(?i)password\s*[=:]\s*["\']?([^\s"\']{4,64})', re.MULTILINE), "Hardcoded password"),
    (re.compile(rb'(?i)passwd\s*[=:]\s*["\']?([^\s"\']{4,64})', re.MULTILINE),   "Hardcoded passwd"),
    (re.compile(rb'(?i)secret\s*[=:]\s*["\']?([^\s"\']{4,64})', re.MULTILINE),   "Hardcoded secret"),
    (re.compile(rb'(?i)api[_-]?key\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,64})',
                re.MULTILINE), "API key"),
    (re.compile(rb'(?i)token\s*[=:]\s*["\']?([A-Za-z0-9_\-]{16,128})',
                re.MULTILINE), "Authentication token"),
    (re.compile(rb'(?i)private[_-]?key\s*[=:][^\n]{4,80}',
                re.MULTILINE), "Private key reference"),
    (re.compile(rb'-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----'),
     "Embedded private key (PEM)"),
    (re.compile(rb'(?i)default[_-]?pass(?:word)?\s*[=:]\s*["\']?([^\s"\']{3,32})'),
     "Default password"),
]

# Crypto / hash weaknesses
WEAK_CRYPTO_PATTERNS = [
    (re.compile(rb'(?i)\bmd5\b'),             "MD5 usage (weak hash)"),
    (re.compile(rb'(?i)\bsha1\b'),            "SHA-1 usage (weak hash)"),
    (re.compile(rb'(?i)\bdes\b'),             "DES usage (broken cipher)"),
    (re.compile(rb'(?i)\b3des\b'),            "3DES usage (weak cipher)"),
    (re.compile(rb'(?i)\brc4\b'),             "RC4 usage (broken cipher)"),
    (re.compile(rb'(?i)EVP_md5|EVP_sha1|EVP_des'), "OpenSSL weak API call"),
    (re.compile(rb'(?i)crypt\('),             "crypt() — potentially weak hash"),
    (re.compile(rb'sslv2|sslv3|tlsv1\.0|tlsv1\.1',
                re.IGNORECASE),               "Deprecated SSL/TLS version"),
]

# Network indicators
NETWORK_PATTERNS = [
    (re.compile(rb'0\.0\.0\.0'),              "Bind-all listener (0.0.0.0)"),
    (re.compile(rb'(?i)telnet'),              "Telnet reference (unencrypted)"),
    (re.compile(rb'(?i)\bftp\b'),            "FTP reference (unencrypted)"),
    (re.compile(rb'(?i)\bhttp://[^\s"\']{4,}'), "Plaintext HTTP URL"),
    (re.compile(rb'\b(?:23|21)\b\s*(?:tcp|udp)',
                re.IGNORECASE),               "Telnet/FTP port reference"),
    (re.compile(rb'(?i)backdoor'),            "Backdoor string detected"),
    (re.compile(rb'(?i)dropbear|openssh|sshd'), "SSH daemon reference"),
    (re.compile(rb'(?i)nc\s+-l|-e\s+/bin/(?:sh|bash)'),
     "Netcat shell/listener"),
]

# Dangerous system calls / functions (binary analysis)
DANGEROUS_FUNCTIONS = [
    b"strcpy", b"strcat", b"sprintf", b"gets", b"scanf",
    b"system", b"popen", b"execve", b"execl", b"execlp",
    b"memcpy", b"memmove", b"strncpy", b"strncat",
    b"printf\x00", b"fprintf\x00",
]

# SUID/SGID indicators
SUID_PATTERNS = [
    (re.compile(rb'chmod\s+[0-9]*[4-7][0-9]{3}'), "SUID/SGID permission set"),
    (re.compile(rb'chmod.*[+]s'),                  "Setuid bit applied"),
]

# Sensitive file paths
SENSITIVE_PATHS = [
    (re.compile(rb'/etc/passwd'),      "Reference to /etc/passwd"),
    (re.compile(rb'/etc/shadow'),      "Reference to /etc/shadow (password hashes)"),
    (re.compile(rb'/etc/sudoers'),     "Reference to /etc/sudoers"),
    (re.compile(rb'/proc/'),           "Reference to /proc filesystem"),
    (re.compile(rb'/dev/mem'),         "Reference to /dev/mem (direct memory access)"),
    (re.compile(rb'/etc/ssl/private'), "Reference to SSL private key directory"),
]

# Known bad strings
BAD_STRINGS = [
    (re.compile(rb'(?i)admin:admin'),   "Default admin:admin credential"),
    (re.compile(rb'(?i)root:root'),     "Default root:root credential"),
    (re.compile(rb'(?i)guest:guest'),   "Default guest:guest credential"),
    (re.compile(rb'(?i)user:user'),     "Default user:user credential"),
    (re.compile(rb'(?i)1234|password1|letmein|qwerty|admin123',
                re.MULTILINE),          "Common/default password string"),
    (re.compile(rb'(?i)TODO.*(?:security|auth|crypt|pass)',
                re.MULTILINE),          "Unresolved security TODO"),
    (re.compile(rb'(?i)FIXME.*(?:security|auth|crypt|pass)',
                re.MULTILINE),          "Unresolved FIXME in security code"),
]

# ELF/binary markers
ELF_MAGIC    = b'\x7fELF'
PE_MAGIC     = b'MZ'
SQUASHFS_MAGIC = b'sqsh'
CRAMFS_MAGIC   = b'\x45\x3d\xcd\x28'


# ---------------------------------------------------------------------------
#  Helpers
# ---------------------------------------------------------------------------

def entropy(data: bytes) -> float:
    """Shannon entropy of a byte sequence."""
    if not data:
        return 0.0
    freq = defaultdict(int)
    for b in data:
        freq[b] += 1
    n = len(data)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def is_text(data: bytes, sample=4096) -> bool:
    """Heuristic: >85% printable ASCII → likely text."""
    chunk = data[:sample]
    if not chunk:
        return False
    printable = sum(1 for b in chunk if 0x09 <= b <= 0x7e or b in (0x0a, 0x0d))
    return printable / len(chunk) > 0.85


def find_strings(data: bytes, min_len=6) -> list:
    """Extract printable ASCII strings from binary data."""
    pattern = re.compile(b'[ -~]{' + str(min_len).encode() + b',}')
    return [m.group().decode("ascii", errors="replace") for m in pattern.finditer(data)]


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def md5_file(path: str) -> str:
    h = hashlib.md5()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------
#  Main Analyzer
# ---------------------------------------------------------------------------

class FirmwareAnalyzer:
    def __init__(self, filepath: str):
        self.filepath  = filepath
        self.findings  = []
        self.meta      = {}
        self._tmpdir   = None

    # ------------------------------------------------------------------ #
    #  Public: generator that yields progress / finding dicts             #
    # ------------------------------------------------------------------ #
    def analyze(self):
        try:
            self._tmpdir = tempfile.mkdtemp(prefix="fwguard_")
            yield from self._run()
        finally:
            if self._tmpdir and os.path.exists(self._tmpdir):
                shutil.rmtree(self._tmpdir, ignore_errors=True)

    # ------------------------------------------------------------------ #
    #  Orchestration                                                       #
    # ------------------------------------------------------------------ #
    def _run(self):
        path = self.filepath
        ext  = Path(path).suffix.lower()
        size = os.path.getsize(path)

        # --- Meta ---
        yield self._progress(2, "Collecting file metadata…")
        self.meta = self._collect_meta(path, size, ext)

        # --- Raw binary pass ---
        yield self._progress(8, "Reading file header and entropy…")
        with open(path, "rb") as f:
            header = f.read(65536)   # first 64 KB
        yield from self._check_header(header, ext, path)

        # --- Entropy check (whole file) ---
        yield self._progress(14, "Calculating file entropy…")
        with open(path, "rb") as f:
            raw = f.read()
        ent = entropy(raw)
        self.meta["entropy"] = round(ent, 3)
        if ent > 7.5:
            yield self._finding(HIGH, "Encryption/Compression",
                                "Very high entropy — file may be encrypted or packed",
                                f"Entropy={ent:.3f} (max 8.0). Encrypted regions obstruct analysis.")
        elif ent > 6.8:
            yield self._finding(MEDIUM, "Encryption/Compression",
                                "Elevated entropy — possible compressed or partially encrypted region",
                                f"Entropy={ent:.3f}")

        # --- Pattern scan on raw bytes ---
        yield self._progress(20, "Scanning for credential patterns…")
        yield from self._pattern_scan(raw, path, CREDENTIAL_PATTERNS,
                                      HIGH, "Credentials / Secrets")

        yield self._progress(30, "Scanning for weak cryptography…")
        yield from self._pattern_scan(raw, path, WEAK_CRYPTO_PATTERNS,
                                      MEDIUM, "Weak Cryptography")

        yield self._progress(38, "Scanning for network indicators…")
        yield from self._pattern_scan(raw, path, NETWORK_PATTERNS,
                                      MEDIUM, "Network / Services")

        yield self._progress(44, "Scanning for dangerous paths…")
        yield from self._pattern_scan(raw, path, SENSITIVE_PATHS,
                                      LOW, "Sensitive File Paths")

        yield self._progress(48, "Scanning for default credentials…")
        yield from self._pattern_scan(raw, path, BAD_STRINGS,
                                      CRITICAL, "Default / Weak Credentials")

        yield self._progress(52, "Scanning for permission issues…")
        yield from self._pattern_scan(raw, path, SUID_PATTERNS,
                                      MEDIUM, "File Permissions")

        # --- ELF binary checks ---
        if header[:4] == ELF_MAGIC:
            yield self._progress(58, "Analyzing ELF binary…")
            yield from self._check_elf(raw, path)

        # --- Archive extraction & recursive scan ---
        yield self._progress(62, "Attempting archive extraction…")
        extracted = self._try_extract(path, ext, raw, header)
        if extracted:
            yield self._finding(INFO, "Archive",
                                f"Archive extracted successfully",
                                f"Extracted to temp dir for recursive analysis")
            yield self._progress(68, "Scanning extracted contents…")
            yield from self._scan_directory(extracted)
        else:
            yield self._finding(INFO, "Archive",
                                "File could not be extracted as archive",
                                "Raw binary analysis only — extraction tools may be needed")

        # --- String extraction analysis ---
        yield self._progress(82, "Extracting and analysing strings…")
        yield from self._check_strings(raw)

        # --- Known CVE signatures ---
        yield self._progress(90, "Checking known vulnerability signatures…")
        yield from self._check_known_signatures(raw)

        # --- Summary info finding ---
        yield self._progress(97, "Finalising report…")
        self._add_summary_info()

        yield self._progress(100, "Analysis complete.")

    # ------------------------------------------------------------------ #
    #  Meta                                                                #
    # ------------------------------------------------------------------ #
    def _collect_meta(self, path, size, ext):
        return {
            "filename":    os.path.basename(path),
            "filepath":    path,
            "size_bytes":  size,
            "size_human":  self._fmt_size(size),
            "extension":   ext,
            "sha256":      sha256_file(path),
            "md5":         md5_file(path),
            "scan_time":   datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

    # ------------------------------------------------------------------ #
    #  Header checks                                                       #
    # ------------------------------------------------------------------ #
    def _check_header(self, header, ext, path):
        detected = "unknown"
        if header[:4] == ELF_MAGIC:
            detected = "ELF binary"
            ei_class = header[4] if len(header) > 4 else 0
            bits = {1: "32-bit", 2: "64-bit"}.get(ei_class, "unknown-width")
            yield self._finding(INFO, "File Type", f"ELF binary detected ({bits})", path)

        elif header[:2] == PE_MAGIC:
            detected = "PE/COFF (Windows executable)"
            yield self._finding(INFO, "File Type", "PE/COFF Windows executable detected", path)

        elif header[:4] == b'PK\x03\x04':
            detected = "ZIP archive"
            yield self._finding(INFO, "File Type", "ZIP archive detected", path)

        elif header[:5] in (b'BZh91', b'BZh61'):
            detected = "bzip2 compressed"
            yield self._finding(INFO, "File Type", "bzip2 compressed data detected", path)

        elif header[:2] == b'\x1f\x8b':
            detected = "gzip compressed"
            yield self._finding(INFO, "File Type", "gzip compressed data detected", path)

        elif header[:6] == b'\xfd7zXZ\x00':
            detected = "XZ compressed"
            yield self._finding(INFO, "File Type", "XZ compressed data detected", path)

        elif b'hsqs' in header[:4] or b'sqsh' in header[:4]:
            detected = "SquashFS filesystem"
            yield self._finding(INFO, "File Type", "SquashFS filesystem image detected", path)

        elif header[:4] == b'\x28\xb5\x2f\xfd':
            detected = "Zstandard compressed"
            yield self._finding(INFO, "File Type", "Zstandard compressed data detected", path)

        elif header[:4] in (b'\x55\xAA\x00\x00', b'\xEB\x58\x90'):
            detected = "Disk image / MBR"
            yield self._finding(MEDIUM, "File Type",
                                "Disk image with MBR detected",
                                "Contains bootloader sector — check for bootkits")

        elif b'ISO 9660' in header or b'CD001' in header:
            detected = "ISO 9660 CD/DVD image"
            yield self._finding(INFO, "File Type", "ISO 9660 optical disc image detected", path)

        elif header[:4] == b'\x7bRIFF':
            yield self._finding(INFO, "File Type", "RIFF/WAV container detected", path)

        # Null-byte padding check
        if header.count(b'\x00') / max(len(header), 1) > 0.6:
            yield self._finding(LOW, "Structure",
                                "High null-byte ratio — may be sparse/padded image",
                                "Could contain hidden data regions or poor firmware packaging")

        self.meta["detected_type"] = detected

    # ------------------------------------------------------------------ #
    #  Generic pattern scanner                                             #
    # ------------------------------------------------------------------ #
    def _pattern_scan(self, data, label, patterns, default_sev, category):
        seen = set()
        for pat, title in patterns:
            for m in pat.finditer(data):
                key = (title, m.start() // 4096)  # de-dup per 4K block
                if key in seen:
                    continue
                seen.add(key)
                ctx = data[max(0, m.start()-30):m.start()+60].replace(b'\x00', b'.')
                ctx_str = ctx.decode("ascii", errors="replace").strip()
                detail = f"Offset 0x{m.start():08x} | …{ctx_str}…"
                yield self._finding(default_sev, category, title, detail)
                if len(seen) > 200:  # safety cap
                    return

    # ------------------------------------------------------------------ #
    #  ELF-specific checks                                                 #
    # ------------------------------------------------------------------ #
    def _check_elf(self, data, path):
        # Check for NX/DEP, stack canaries, RELRO, PIE
        checks = {
            b"__stack_chk_fail": ("Stack canary",     OK,  "Stack smash protection present"),
            b"__fortify_fail":   ("FORTIFY_SOURCE",   OK,  "FORTIFY_SOURCE hardening present"),
            b"__asan_init":      ("AddressSanitizer",  INFO, "AddressSanitizer enabled (debug build?)"),
        }
        found = set()
        for marker, (name, sev, msg) in checks.items():
            if marker in data:
                found.add(name)
                yield self._finding(sev, "Binary Hardening", msg, path)

        if "Stack canary" not in found:
            yield self._finding(HIGH, "Binary Hardening",
                                "No stack canary detected",
                                "Binary compiled without -fstack-protector — vulnerable to stack overflow")

        # PIE check (ELF type 0x0003 = ET_DYN with PIE)
        if len(data) >= 18:
            elf_type = struct.unpack_from("<H", data, 16)[0]
            if elf_type == 2:  # ET_EXEC — not PIE
                yield self._finding(MEDIUM, "Binary Hardening",
                                    "Non-PIE executable (fixed base address)",
                                    "Increases ROP/JIT spray attack surface; compile with -fPIE -pie")
            elif elf_type == 3:
                yield self._finding(OK, "Binary Hardening",
                                    "PIE (Position Independent Executable) enabled", path)

        # Dangerous libc functions
        found_dangerous = []
        for fn in DANGEROUS_FUNCTIONS:
            if fn in data:
                found_dangerous.append(fn.rstrip(b'\x00').decode())
        if found_dangerous:
            yield self._finding(HIGH, "Dangerous Functions",
                                "Unsafe C functions found in binary",
                                ", ".join(found_dangerous))

        # RPATH/RUNPATH injection risk
        if b'RPATH' in data or b'RUNPATH' in data or b'/tmp' in data:
            yield self._finding(MEDIUM, "Binary Hardening",
                                "RPATH / /tmp reference in binary",
                                "May allow library injection attacks")

    # ------------------------------------------------------------------ #
    #  Archive extraction                                                  #
    # ------------------------------------------------------------------ #
    def _try_extract(self, path, ext, raw, header):
        out = os.path.join(self._tmpdir, "extracted")
        os.makedirs(out, exist_ok=True)

        # ZIP
        if zipfile.is_zipfile(path):
            try:
                with zipfile.ZipFile(path) as zf:
                    self._safe_extract_zip(zf, out)
                return out
            except Exception:
                pass

        # TAR (including .tar.gz, .tgz, .tar.bz2, .tar.xz)
        if tarfile.is_tarfile(path):
            try:
                with tarfile.open(path, "r:*") as tf:
                    members = [m for m in tf.getmembers()
                               if not m.name.startswith("/") and ".." not in m.name]
                    tf.extractall(out, members=members)
                return out
            except Exception:
                pass

        # GZIP (single file)
        if raw[:2] == b'\x1f\x8b':
            try:
                inner = os.path.join(out, Path(path).stem)
                with gzip.open(path, "rb") as gz, open(inner, "wb") as dst:
                    shutil.copyfileobj(gz, dst)
                return out
            except Exception:
                pass

        return None

    def _safe_extract_zip(self, zf, dest):
        """Extract ZIP with path traversal protection."""
        dest = os.path.realpath(dest)
        for info in zf.infolist():
            target = os.path.realpath(os.path.join(dest, info.filename))
            if not target.startswith(dest):
                continue  # path traversal — skip
            if info.is_dir():
                os.makedirs(target, exist_ok=True)
            else:
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with zf.open(info) as src, open(target, "wb") as dst:
                    shutil.copyfileobj(src, dst)

    # ------------------------------------------------------------------ #
    #  Recursive directory scan                                            #
    # ------------------------------------------------------------------ #
    def _scan_directory(self, dirpath):
        file_count  = 0
        world_write = []
        suid_files  = []

        for root, dirs, files in os.walk(dirpath):
            # Skip deeply nested dirs (bomb protection)
            depth = root[len(dirpath):].count(os.sep)
            if depth > 12:
                dirs.clear()
                continue

            for fname in files:
                fpath = os.path.join(root, fname)
                rel   = os.path.relpath(fpath, dirpath)
                file_count += 1

                # Size guard
                try:
                    fsize = os.path.getsize(fpath)
                except OSError:
                    continue
                if fsize > 50 * 1024 * 1024:  # skip >50MB sub-files
                    continue

                # Permission checks (Unix)
                try:
                    mode = os.stat(fpath).st_mode
                    if mode & 0o002:  # world-writable
                        world_write.append(rel)
                    if mode & 0o4000 or mode & 0o2000:  # SUID/SGID
                        suid_files.append(rel)
                except Exception:
                    pass

                # Scan text/binary content
                try:
                    with open(fpath, "rb") as f:
                        fdata = f.read(min(fsize, 4 * 1024 * 1024))  # max 4MB per file
                except OSError:
                    continue

                ext = Path(fname).suffix.lower()

                # Run patterns on extracted file
                yield from self._pattern_scan(fdata, rel, CREDENTIAL_PATTERNS,
                                              HIGH, f"Credentials [{rel}]")
                yield from self._pattern_scan(fdata, rel, WEAK_CRYPTO_PATTERNS,
                                              MEDIUM, f"Weak Crypto [{rel}]")
                yield from self._pattern_scan(fdata, rel, BAD_STRINGS,
                                              CRITICAL, f"Default Creds [{rel}]")

                # ELF sub-binaries
                if fdata[:4] == ELF_MAGIC:
                    yield from self._check_elf(fdata, rel)

                # Config file checks
                if ext in (".conf", ".cfg", ".ini", ".json", ".xml",
                           ".yaml", ".yml", ".env", ".properties"):
                    yield from self._check_config(fdata, rel)

                # Script checks
                if ext in (".sh", ".bash", ".py", ".pl", ".rb", ".lua"):
                    yield from self._check_script(fdata, rel)

        if world_write:
            yield self._finding(HIGH, "File Permissions",
                                f"World-writable files found ({len(world_write)})",
                                ", ".join(world_write[:5]) +
                                ("…" if len(world_write) > 5 else ""))
        if suid_files:
            yield self._finding(HIGH, "File Permissions",
                                f"SUID/SGID files found ({len(suid_files)})",
                                ", ".join(suid_files[:5]) +
                                ("…" if len(suid_files) > 5 else ""))

        yield self._finding(INFO, "Archive Contents",
                            f"Total files in archive: {file_count}", dirpath)

    # ------------------------------------------------------------------ #
    #  Config file analysis                                                #
    # ------------------------------------------------------------------ #
    def _check_config(self, data, label):
        text = data.decode("utf-8", errors="replace")

        # Cleartext credentials in config
        for pat_str in [
            r'(?i)password\s*[=:]\s*(.+)',
            r'(?i)passwd\s*[=:]\s*(.+)',
            r'(?i)secret\s*[=:]\s*(.+)',
        ]:
            for m in re.finditer(pat_str, text):
                val = m.group(1).strip().strip('"\'')
                if val and val.lower() not in ("", "none", "null", "''", '""', "changeme"):
                    yield self._finding(HIGH, "Config — Credentials",
                                        "Credential found in config file",
                                        f"{label}: {m.group(0)[:80]}")
                    break

        # Debug / verbose mode
        if re.search(r'(?i)debug\s*=\s*(true|1|yes|on)', text):
            yield self._finding(LOW, "Config — Debug",
                                "Debug mode enabled in config",
                                f"{label}")

        # Disabled TLS verification
        if re.search(r'(?i)(verify_ssl|ssl_verify|tls_verify)\s*[=:]\s*(false|0|no|off)', text):
            yield self._finding(HIGH, "Config — TLS",
                                "TLS certificate verification disabled",
                                f"{label} — disabling cert verification allows MITM attacks")

        # Wildcard CORS
        if re.search(r'(?i)Access-Control-Allow-Origin\s*:\s*\*', text):
            yield self._finding(MEDIUM, "Config — CORS",
                                "Wildcard CORS policy configured",
                                f"{label}")

    # ------------------------------------------------------------------ #
    #  Script analysis                                                     #
    # ------------------------------------------------------------------ #
    def _check_script(self, data, label):
        text = data.decode("utf-8", errors="replace")

        # eval of untrusted input
        if re.search(r'\beval\b', text):
            yield self._finding(MEDIUM, "Script — Code Injection",
                                "eval() usage in script",
                                f"{label} — eval of dynamic input is dangerous")

        # Curl/wget piped to shell
        if re.search(r'(?:curl|wget).+\|\s*(?:bash|sh)', text):
            yield self._finding(HIGH, "Script — Remote Execution",
                                "curl/wget piped to shell",
                                f"{label} — downloads and executes remote code")

        # rm -rf /
        if re.search(r'rm\s+-[rf]+\s+/', text):
            yield self._finding(CRITICAL, "Script — Destructive Command",
                                "Destructive rm -rf / command found",
                                f"{label}")

        # Hardcoded IPs
        ips = re.findall(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', text)
        public_ips = [ip for ip in ips if not ip.startswith(
            ("192.168.", "10.", "172.", "127.", "0."))]
        if public_ips:
            yield self._finding(MEDIUM, "Script — Hardcoded IP",
                                f"Hardcoded public IP addresses ({len(public_ips)})",
                                f"{label}: {', '.join(set(public_ips)[:4])}")

    # ------------------------------------------------------------------ #
    #  String analysis                                                     #
    # ------------------------------------------------------------------ #
    def _check_strings(self, data):
        strings = find_strings(data, min_len=8)

        # IP addresses
        public_ips = set()
        for s in strings:
            for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b', s):
                ip = m.group(1)
                if not ip.startswith(("192.168.", "10.", "172.", "127.", "0.", "255.")):
                    public_ips.add(ip)
        if public_ips:
            yield self._finding(MEDIUM, "Embedded Addresses",
                                f"Hardcoded public IP addresses ({len(public_ips)})",
                                ", ".join(sorted(public_ips)[:8]))

        # URLs
        urls = set()
        for s in strings:
            for m in re.finditer(r'https?://[^\s"\'<>]{6,}', s):
                urls.add(m.group(0)[:80])
        if urls:
            http_only = [u for u in urls if u.startswith("http://")]
            if http_only:
                yield self._finding(MEDIUM, "Embedded URLs",
                                    f"Plaintext HTTP URLs found ({len(http_only)})",
                                    "; ".join(list(http_only)[:4]))
            yield self._finding(INFO, "Embedded URLs",
                                f"Total URLs found: {len(urls)}",
                                "; ".join(list(urls)[:3]))

        # Email addresses
        emails = set()
        for s in strings:
            for m in re.finditer(r'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}', s):
                emails.add(m.group(0))
        if emails:
            yield self._finding(LOW, "Embedded Addresses",
                                f"Email addresses embedded ({len(emails)})",
                                ", ".join(list(emails)[:4]))

    # ------------------------------------------------------------------ #
    #  Known vulnerability signatures                                      #
    # ------------------------------------------------------------------ #
    def _check_known_signatures(self, data):
        sigs = [
            (b"CVE-2017-5638",         CRITICAL, "CVE-2017-5638 (Apache Struts RCE) string found"),
            (b"CVE-2021-44228",        CRITICAL, "CVE-2021-44228 (Log4Shell) string found"),
            (b"CVE-2014-0160",         CRITICAL, "CVE-2014-0160 (Heartbleed) string found"),
            (b"CVE-2017-7494",         CRITICAL, "CVE-2017-7494 (SambaCry) string found"),
            (b"shellshock",            CRITICAL, "Shellshock reference found"),
            (b"log4j",                 HIGH,     "Log4j library reference — check for CVE-2021-44228"),
            (b"struts",                HIGH,     "Apache Struts reference — verify version"),
            (b"openssl",               INFO,     "OpenSSL reference — verify version is current"),
            (b"libssl.so.1.0",         HIGH,     "OpenSSL 1.0.x linked — known vulnerable versions"),
            (b"libcrypto.so.1.0",      HIGH,     "OpenSSL 1.0.x crypto library linked"),
            (b"libssl.so.1.1",         MEDIUM,   "OpenSSL 1.1.x — check if latest patch applied"),
            (b"glibc-2.1",             HIGH,     "Old glibc version linked"),
            (b"utelnetd",              HIGH,     "uTelnetd (unsecured telnet daemon) found"),
            (b"busybox",               INFO,     "BusyBox embedded — check version for known CVEs"),
            (b"dropbear",              INFO,     "Dropbear SSH — verify version for known CVEs"),
            (b"uhttpd",                INFO,     "uhttpd web server — common in router firmware"),
            (b"/bin/sh",               MEDIUM,   "Shell reference (/bin/sh) in binary"),
            (b"NVRAM",                 INFO,     "NVRAM reference — check for credential storage"),
            (b"cfg_manager",           INFO,     "Config manager reference"),
        ]
        seen_sigs = set()
        for sig, sev, msg in sigs:
            if sig in data and sig not in seen_sigs:
                seen_sigs.add(sig)
                yield self._finding(sev, "Known Signatures", msg,
                                    f"Signature: {sig.decode('ascii', errors='replace')}")

    # ------------------------------------------------------------------ #
    #  Summary INFO findings                                               #
    # ------------------------------------------------------------------ #
    def _add_summary_info(self):
        m = self.meta
        self._emit(INFO, "File Metadata", "SHA-256 hash",  m.get("sha256",""))
        self._emit(INFO, "File Metadata", "MD5 hash",      m.get("md5",""))
        self._emit(INFO, "File Metadata", "File size",     m.get("size_human",""))
        self._emit(INFO, "File Metadata", "Detected type", m.get("detected_type","unknown"))
        self._emit(INFO, "File Metadata", "Shannon entropy", str(m.get("entropy","?")))

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #
    def _finding(self, severity, category, title, detail=""):
        kb = get_knowledge(title)
        f = {
            "severity":    severity,
            "category":    category,
            "title":       title,
            "detail":      str(detail)[:300],
            "description": kb.get("description", ""),
            "impact":      kb.get("impact", ""),
            "remediation": kb.get("remediation", ""),
            "references":  kb.get("references", []),
            "cvss":        kb.get("cvss", ""),
        }
        self.findings.append(f)
        return {"type": "finding", **f}

    def _emit(self, severity, category, title, detail=""):
        kb = get_knowledge(title)
        f = {
            "severity":    severity,
            "category":    category,
            "title":       title,
            "detail":      str(detail)[:300],
            "description": kb.get("description", ""),
            "impact":      kb.get("impact", ""),
            "remediation": kb.get("remediation", ""),
            "references":  kb.get("references", []),
            "cvss":        kb.get("cvss", ""),
        }
        self.findings.append(f)

    def _progress(self, value, message):
        return {"type": "progress", "value": value, "message": message}

    @staticmethod
    def _fmt_size(n):
        for u in ("B", "KB", "MB", "GB"):
            if n < 1024:
                return f"{n:.1f} {u}"
            n /= 1024
        return f"{n:.1f} TB"
