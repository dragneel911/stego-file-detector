PATTERNS = [
    ("certutil", "downloads/decodes files via certutil, a common LOLBin technique"),
    ("bitsadmin", "downloads files via BITS, a common LOLBin technique"),
    ("powershell -enc", "runs base64-encoded PowerShell, often used to hide commands"),
    ("curl", "downloads files via curl"),
    ("wget", "downloads files via wget"),
    ("netsh firewall", "modifies firewall settings, possibly to disable protection"),
    ("sc stop", "stops a Windows service, possibly a security service"),
    ("base64", "references base64 encoding, often used to obfuscate commands"),
    ("reg add", "modifies the registry, possibly for persistence"),
    ("schtasks", "creates a scheduled task, a common persistence technique"),
]


def scan_bat(text: str) -> tuple[bool, list[str]]:
    findings = []
    for line_number, line in enumerate(text.splitlines(), start=1):
        lower_line = line.lower()
        for keyword, reason in PATTERNS:
            if keyword in lower_line:
                findings.append(f"Line {line_number}: matched '{keyword}' - {reason}")
    return (len(findings) > 0, findings)
