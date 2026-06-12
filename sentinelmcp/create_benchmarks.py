import json
import os

BASE = "benchmark/cases"
os.makedirs(BASE, exist_ok=True)

cases = {
    "ransomware": {
        "case": {
            "id": "case-ransomware-001",
            "description": "Ransomware infection with encryption and shadow copy deletion",
            "disk_path": "/evidence/ransomware/disk.E01",
            "memory_path": "/evidence/ransomware/mem.dmp",
            "pcap_path": "/evidence/ransomware/capture.pcap",
            "tags": ["ransomware", "encryption", "vssadmin"]
        },
        "gt": {
            "known_evil_iocs": [
                {"type": "hash", "value": "a1b2c3d4ransomware", "description": "Ransomware binary"},
                {"type": "domain", "value": "ransom-c2.evil.com", "description": "C2 domain"}
            ],
            "known_clean_entities": [
                {"type": "process", "value": "svchost.exe", "description": "Legitimate service host"}
            ],
            "attack_timeline": [
                {"time": "2024-01-15T02:00:00Z", "event": "Ransomware binary dropped to %TEMP%"},
                {"time": "2024-01-15T02:01:00Z", "event": "vssadmin.exe delete shadows /all /quiet"},
                {"time": "2024-01-15T02:02:00Z", "event": "Mass file encryption begins (.docx .xlsx .pdf)"},
                {"time": "2024-01-15T02:15:00Z", "event": "Ransom note dropped to Desktop"}
            ]
        }
    },
    "insider_threat": {
        "case": {
            "id": "case-insider-001",
            "description": "Insider threat — unusual data access and exfil staging",
            "disk_path": "/evidence/insider/disk.E01",
            "memory_path": "/evidence/insider/mem.dmp",
            "pcap_path": "/evidence/insider/capture.pcap",
            "tags": ["insider", "data-staging", "unusual-access"]
        },
        "gt": {
            "known_evil_iocs": [
                {"type": "path", "value": "C:\\Users\\jdoe\\Documents\\archive.7z", "description": "Staged data archive"},
                {"type": "ip", "value": "203.0.113.45", "description": "Personal cloud storage IP"}
            ],
            "known_clean_entities": [
                {"type": "process", "value": "outlook.exe", "description": "Normal email client"}
            ],
            "attack_timeline": [
                {"time": "2024-02-10T03:30:00Z", "event": "User jdoe accesses sensitive HR share at 03:30 AM"},
                {"time": "2024-02-10T04:00:00Z", "event": "7-Zip used to archive 2.3GB of HR documents"},
                {"time": "2024-02-10T04:05:00Z", "event": "Large outbound transfer to personal Dropbox"}
            ]
        }
    },
    "supply_chain": {
        "case": {
            "id": "case-supply-chain-001",
            "description": "Supply chain compromise via trusted software updater",
            "disk_path": "/evidence/supply_chain/disk.E01",
            "memory_path": "/evidence/supply_chain/mem.dmp",
            "pcap_path": "/evidence/supply_chain/capture.pcap",
            "tags": ["supply-chain", "signed-binary", "updater"]
        },
        "gt": {
            "known_evil_iocs": [
                {"type": "hash", "value": "evil_signed_update_sha256", "description": "Trojanised update package"},
                {"type": "domain", "value": "update.legit-software-evil.com", "description": "Typosquatted update server"}
            ],
            "known_clean_entities": [
                {"type": "hash", "value": "legit_update_sha256", "description": "Legitimate update binary"}
            ],
            "attack_timeline": [
                {"time": "2024-03-01T10:00:00Z", "event": "Legitimate-looking signed updater executes"},
                {"time": "2024-03-01T10:00:05Z", "event": "Updater spawns cmd.exe — unexpected child process"},
                {"time": "2024-03-01T10:01:00Z", "event": "Backdoor establishes persistence via Run key"}
            ]
        }
    },
    "living_off_the_land": {
        "case": {
            "id": "case-lolbas-001",
            "description": "Living-off-the-land attack using PowerShell, WMIC, and rundll32",
            "disk_path": "/evidence/lolbas/disk.E01",
            "memory_path": "/evidence/lolbas/mem.dmp",
            "pcap_path": "/evidence/lolbas/capture.pcap",
            "tags": ["lolbas", "powershell", "wmic", "rundll32"]
        },
        "gt": {
            "known_evil_iocs": [
                {"type": "path", "value": "powershell -enc JABpAG0...", "description": "Base64-encoded PS payload"},
                {"type": "ip", "value": "198.51.100.99", "description": "Attacker C2 IP"}
            ],
            "known_clean_entities": [
                {"type": "process", "value": "powershell.exe", "description": "PowerShell — benign if invocation is normal"}
            ],
            "attack_timeline": [
                {"time": "2024-04-05T14:00:00Z", "event": "PowerShell invoked with -enc flag and encoded payload"},
                {"time": "2024-04-05T14:00:10Z", "event": "WMIC spawned for WMI persistence subscription"},
                {"time": "2024-04-05T14:01:00Z", "event": "rundll32.exe loads malicious DLL from %APPDATA%"}
            ]
        }
    },
    "credential_theft": {
        "case": {
            "id": "case-cred-theft-001",
            "description": "Credential theft via LSASS memory dumping (T1003)",
            "disk_path": "/evidence/cred_theft/disk.E01",
            "memory_path": "/evidence/cred_theft/mem.dmp",
            "pcap_path": "/evidence/cred_theft/capture.pcap",
            "tags": ["credential-theft", "lsass", "mimikatz", "T1003"]
        },
        "gt": {
            "known_evil_iocs": [
                {"type": "hash", "value": "mimikatz_sha256_abc123", "description": "Mimikatz binary"},
                {"type": "path", "value": "C:\\Windows\\Temp\\lsass.dmp", "description": "LSASS dump file"}
            ],
            "known_clean_entities": [
                {"type": "process", "value": "lsass.exe", "description": "Legitimate LSASS — victim not attacker"}
            ],
            "attack_timeline": [
                {"time": "2024-05-20T03:00:00Z", "event": "mimikatz.exe dropped to Temp directory"},
                {"time": "2024-05-20T03:00:10Z", "event": "sekurlsa::logonpasswords executed against LSASS"},
                {"time": "2024-05-20T03:00:20Z", "event": "Credential hashes written to lsass.dmp"},
                {"time": "2024-05-20T03:01:00Z", "event": "Pass-the-hash lateral movement initiated"}
            ]
        }
    },
    "data_exfiltration": {
        "case": {
            "id": "case-exfil-001",
            "description": "Data exfiltration via archive creation and outbound HTTPS transfer",
            "disk_path": "/evidence/exfil/disk.E01",
            "memory_path": "/evidence/exfil/mem.dmp",
            "pcap_path": "/evidence/exfil/capture.pcap",
            "tags": ["exfiltration", "archive", "outbound-transfer", "T1041"]
        },
        "gt": {
            "known_evil_iocs": [
                {"type": "ip", "value": "203.0.113.200", "description": "Exfil destination IP"},
                {"type": "path", "value": "C:\\Users\\Public\\data.zip", "description": "Staged zip archive"}
            ],
            "known_clean_entities": [
                {"type": "process", "value": "chrome.exe", "description": "Legitimate browser"}
            ],
            "attack_timeline": [
                {"time": "2024-06-12T22:00:00Z", "event": "WinRAR archives sensitive directories"},
                {"time": "2024-06-12T22:05:00Z", "event": "curl.exe uploads archive to attacker server"},
                {"time": "2024-06-12T22:10:00Z", "event": "Archive and tool artefacts deleted from disk"}
            ]
        }
    },
    "clean_baseline": {
        "case": {
            "id": "case-clean-001",
            "description": "Clean baseline — benign workstation activity, no compromise",
            "disk_path": "/evidence/clean/disk.E01",
            "memory_path": "/evidence/clean/mem.dmp",
            "pcap_path": "/evidence/clean/capture.pcap",
            "tags": ["baseline", "benign", "clean"]
        },
        "gt": {
            "known_evil_iocs": [],
            "known_clean_entities": [
                {"type": "process", "value": "explorer.exe", "description": "Windows shell"},
                {"type": "process", "value": "chrome.exe", "description": "Web browser"},
                {"type": "process", "value": "outlook.exe", "description": "Email client"},
                {"type": "process", "value": "teams.exe", "description": "Collaboration software"}
            ],
            "attack_timeline": []
        }
    }
}

for case_name, data in cases.items():
    path = os.path.join(BASE, case_name)
    os.makedirs(path, exist_ok=True)

    # Sprint 4 GT additions
    gt = data["gt"]
    gt["known_iocs"] = [ioc["value"] for ioc in gt.get("known_evil_iocs", [])]
    gt["timeline_events"] = [ev["event"] for ev in gt.get("attack_timeline", [])]
    gt["attack_chain"] = gt["timeline_events"][:]

    with open(os.path.join(path, "case.json"), "w", encoding="utf-8") as f:
        json.dump(data["case"], f, indent=2)
    with open(os.path.join(path, "ground_truth.json"), "w", encoding="utf-8") as f:
        json.dump(gt, f, indent=2)
    print(f"Created {case_name}")

print("All 7 new benchmark cases created.")
