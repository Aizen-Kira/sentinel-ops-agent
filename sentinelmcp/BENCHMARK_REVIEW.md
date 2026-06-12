# Benchmark Review (RC1)

## Overview
All benchmark cases were reviewed to ensure realism, consistency, and alignment with the new evaluation schema.

## Cases Validated
1. **Ransomware** (`cases/ransomware/`)
   - **Attack Chain Consistency**: Ransomware binary drop -> shadow copy deletion -> encryption -> ransom note.
   - **Timeline Accuracy**: Consistent and sequential timeline.
   - **IOC Correctness**: Hashes and domains correctly mapped to the new schema (`known_iocs`, `timeline_events`).
2. **Lateral Movement** (`cases/lateral_movement/`)
   - **Attack Chain Consistency**: Phishing -> PowerShell download cradle -> PsExec -> LSASS dumping -> Mimikatz.
   - **Timeline Accuracy**: Event sequence flows logically over a 25-minute window.
   - **IOC Correctness**: Corrected the legacy schema (`known_evil`, `known_clean`) to the new unified schema (`known_evil_iocs`, `known_clean_entities`, `known_iocs`, `timeline_events`, `attack_chain`).
3. **Data Exfiltration** (`cases/data_exfiltration/`)
   - **Attack Chain Consistency**: Archiving (WinRAR) -> Exfil via curl -> artefact deletion.
   - **Timeline Accuracy**: Fully accurate and realistic.
   - **IOC Correctness**: IPs and Paths verified.
4. **Credential Theft** (`cases/credential_theft/`)
   - **Attack Chain Consistency**: Mimikatz drop -> sekurlsa::logonpasswords -> dump -> lateral movement.
   - **Timeline Accuracy**: Logical progression.
   - **IOC Correctness**: Hashes and memory paths are correct.
5. **Living off the Land** (`cases/living_off_the_land/`)
   - **Attack Chain Consistency**: PowerShell execution -> WMI persistence -> DLL loaded via rundll32.
   - **Timeline Accuracy**: Timeline reflects instantaneous automation.
   - **IOC Correctness**: Correctly uses benign binaries (powershell, rundll32) with malicious arguments as IOCs.
6. **Insider Threat** (`cases/insider_threat/`)
   - **Attack Chain Consistency**: Sensitive share access -> 7-zip -> Dropbox exfil.
   - **Timeline Accuracy**: Realistic timeline of an insider threat during off-hours.
   - **IOC Correctness**: Includes paths and external IPs.
7. **Supply Chain** (`cases/supply_chain/`)
   - **Attack Chain Consistency**: Signed updater -> cmd.exe spawn -> Run key persistence.
   - **Timeline Accuracy**: Logical payload progression.
   - **IOC Correctness**: Verification of both benign and trojanised hashes.
8. **Clean Baseline** (`cases/clean_baseline/`)
   - Ensures the agent does not hallucinate false positives on a clean machine. 

## Verdict
- **No impossible artifacts** detected.
- **IOCs and Timelines** are correctly populated and mapped to the evaluation metric script (`scorer.py`).
- All benchmarks use the unified RC1 schema and are ready for validation.
