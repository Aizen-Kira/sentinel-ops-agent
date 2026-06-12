// scripts/seed-ransomware-demo.ts
// Generates a realistic 4-hour ransomware attack scenario, seeds Splunk + DB, triggers agent
// Run with: npx tsx server/scripts/seed-ransomware-demo.ts  OR  npm run demo:seed

import { SplunkHecClient, type HecEvent } from "../lib/splunk/splunkHec";

// ─── Helpers ──────────────────────────────────────────────────────────────────

function ts(baseMs: number, offsetMinutes: number, jitterSec = 30): number {
  return (baseMs + offsetMinutes * 60_000 + Math.random() * jitterSec * 1000) / 1000;
}

function randIp(subnet: string): string {
  return `${subnet}.${Math.floor(Math.random() * 254) + 1}`;
}

function pick<T>(arr: T[]): T {
  return arr[Math.floor(Math.random() * arr.length)]!;
}

const CORP_HOSTS = ["ws-001.corp", "ws-002.corp", "ws-047.corp", "dc-001.corp", "fileserver-02.corp", "hr-laptop-12.corp"];
const USERS = ["jdoe@corp.local", "msmith@corp.local", "SYSTEM", "NT AUTHORITY\\NETWORK SERVICE"];
const EXT_IPS = ["185.220.101.42", "91.108.56.121", "193.150.34.7", "45.142.212.100"];
const INTERNAL_SUBNET = "192.168.10";

// ─── Event generators per attack stage ───────────────────────────────────────

function genStage1Recon(base: number, incidentId: number): HecEvent[] {
  const events: HecEvent[] = [];
  for (let i = 0; i < 35; i++) {
    const t = ts(base, i * 0.8);
    events.push({
      time: t,
      event: {
        incident_id: incidentId, attack_stage: 1,
        event_type: pick(["port_scan", "dns_lookup", "ldap_enum"]),
        src_ip: pick(EXT_IPS), dest_ip: randIp(INTERNAL_SUBNET),
        host: pick(CORP_HOSTS), user: "ANONYMOUS",
        severity: "medium",
        mitre_tactic: "Reconnaissance",
        mitre_technique_id: pick(["T1595.001", "T1590.002", "T1589.003"]),
        mitre_technique_name: pick(["Active Scanning: Scanning IP Blocks", "Gather Victim Network Information", "Gather Victim Identity Information: Employee Names"]),
        dest_port: pick([445, 139, 389, 636, 3389, 22, 80, 443]),
        process: "nmap",
        description: "External scanning activity detected",
      },
    });
  }
  return events;
}

function genStage2InitialAccess(base: number, incidentId: number): HecEvent[] {
  const events: HecEvent[] = [];
  const targetHost = "hr-laptop-12.corp";
  const targetUser = "msmith@corp.local";

  events.push({
    time: ts(base, 45),
    event: {
      incident_id: incidentId, attack_stage: 2, event_type: "phishing_click",
      host: targetHost, user: targetUser, src_ip: pick(EXT_IPS),
      dest_ip: "192.168.10.12", severity: "high",
      mitre_tactic: "Initial Access", mitre_technique_id: "T1566.001",
      mitre_technique_name: "Phishing: Spearphishing Attachment",
      url: "http://doc-sharepoint-update.evil.com/invoice.pdf.exe",
      email_subject: "Urgent: Invoice approval needed - Q4 2024",
      file_name: "invoice_Q4_2024.pdf.exe", description: "User clicked phishing link",
    },
  });

  for (let i = 0; i < 15; i++) {
    events.push({
      time: ts(base, 46 + i * 0.5),
      event: {
        incident_id: incidentId, attack_stage: 2, event_type: "malicious_execution",
        host: targetHost, user: targetUser, severity: "critical",
        mitre_tactic: "Execution", mitre_technique_id: "T1204.002",
        mitre_technique_name: "User Execution: Malicious File",
        process: "invoice_Q4_2024.pdf.exe", parent_process: "outlook.exe",
        file_hash: "a1b2c3d4e5f67890abcdef1234567890",
        file_path: `C:\\Users\\msmith\\Downloads\\invoice_Q4_2024.pdf.exe`,
        description: "Malicious payload executed from email attachment",
      },
    });
  }
  return events;
}

function genStage3C2(base: number, incidentId: number): HecEvent[] {
  const events: HecEvent[] = [];
  const c2Ip = "185.220.101.42";
  const beaconHost = "hr-laptop-12.corp";

  for (let i = 0; i < 40; i++) {
    events.push({
      time: ts(base, 55 + i * 2.5),
      event: {
        incident_id: incidentId, attack_stage: 3,
        event_type: pick(["c2_beacon", "encrypted_outbound", "dns_tunnel"]),
        host: beaconHost, user: "msmith@corp.local",
        src_ip: "192.168.10.12", dest_ip: c2Ip,
        dest_port: pick([443, 8443, 4444, 80]),
        severity: "critical",
        mitre_tactic: "Command and Control",
        mitre_technique_id: pick(["T1071.001", "T1132.001", "T1573.002"]),
        mitre_technique_name: pick(["Application Layer Protocol: Web Protocols", "Data Encoding: Standard Encoding", "Encrypted Channel: Asymmetric Cryptography"]),
        bytes_out: Math.floor(Math.random() * 5000) + 200,
        process: "svchost.exe",
        description: "Periodic C2 beacon to external IP",
      },
    });
  }
  return events;
}

function genStage4LateralMovement(base: number, incidentId: number): HecEvent[] {
  const events: HecEvent[] = [];
  const targets = ["ws-001.corp", "ws-002.corp", "dc-001.corp"];

  // Credential dumping
  for (let i = 0; i < 10; i++) {
    events.push({
      time: ts(base, 120 + i),
      event: {
        incident_id: incidentId, attack_stage: 4, event_type: "credential_dump",
        host: "hr-laptop-12.corp", user: "msmith@corp.local",
        severity: "critical", mitre_tactic: "Credential Access",
        mitre_technique_id: "T1003.001",
        mitre_technique_name: "OS Credential Dumping: LSASS Memory",
        process: "mimikatz.exe", target_process: "lsass.exe",
        description: "LSASS memory dumped for credential extraction",
      },
    });
  }

  // Pass-the-hash + RDP
  for (const target of targets) {
    for (let i = 0; i < 10; i++) {
      events.push({
        time: ts(base, 130 + i * 3),
        event: {
          incident_id: incidentId, attack_stage: 4,
          event_type: pick(["pass_the_hash", "rdp_session", "smb_lateral"]),
          host: pick(CORP_HOSTS), dest_host: target,
          user: pick(USERS), severity: "critical",
          mitre_tactic: "Lateral Movement",
          mitre_technique_id: pick(["T1550.002", "T1021.001", "T1021.002"]),
          mitre_technique_name: pick(["Use Alternate Authentication Material: Pass the Hash", "Remote Services: Remote Desktop Protocol", "Remote Services: SMB/Windows Admin Shares"]),
          src_ip: "192.168.10.12", dest_ip: randIp(INTERNAL_SUBNET),
          dest_port: pick([445, 3389, 135]),
          description: `Lateral movement attempt to ${target}`,
        },
      });
    }
  }
  return events;
}

function genStage5Encryption(base: number, incidentId: number): HecEvent[] {
  const events: HecEvent[] = [];
  const encHosts = ["fileserver-02.corp", "dc-001.corp", "ws-047.corp"];
  const extensions = [".docx", ".xlsx", ".pdf", ".sql", ".bak"];

  // File encryption wave
  for (let i = 0; i < 60; i++) {
    const ext = pick(extensions);
    events.push({
      time: ts(base, 185 + Math.floor(i / 10)),
      event: {
        incident_id: incidentId, attack_stage: 5, event_type: "file_encrypt",
        host: pick(encHosts), user: "SYSTEM",
        severity: "critical", mitre_tactic: "Impact",
        mitre_technique_id: "T1486",
        mitre_technique_name: "Data Encrypted for Impact",
        file_path: `\\\\${pick(encHosts)}\\shares\\finance\\report_${i}${ext}`,
        file_original: `report_${i}${ext}`,
        file_renamed: `report_${i}${ext}.locked`,
        description: "File renamed with .locked extension indicating ransomware encryption",
      },
    });
  }

  // Shadow copy deletion
  events.push({
    time: ts(base, 192),
    event: {
      incident_id: incidentId, attack_stage: 5, event_type: "shadow_copy_delete",
      host: "dc-001.corp", user: "SYSTEM",
      severity: "critical", mitre_tactic: "Impact",
      mitre_technique_id: "T1490", mitre_technique_name: "Inhibit System Recovery",
      command: "vssadmin delete shadows /all /quiet",
      process: "cmd.exe", parent_process: "ransomware_payload.exe",
      description: "All VSS shadow copies deleted to prevent recovery",
    },
  });

  // Ransom note
  events.push({
    time: ts(base, 194),
    event: {
      incident_id: incidentId, attack_stage: 5, event_type: "ransom_note_drop",
      host: "fileserver-02.corp", user: "SYSTEM",
      severity: "critical", mitre_tactic: "Impact",
      mitre_technique_id: "T1486",
      file_path: "\\\\fileserver-02.corp\\shares\\README_DECRYPT.txt",
      file_content_preview: "Your files have been encrypted. To recover them...",
      description: "Ransom note dropped on file share",
    },
  });

  return events;
}

// ─── Main seeder ──────────────────────────────────────────────────────────────

async function main() {
  console.log("🦠 Seeding ransomware demo scenario...\n");

  const hec = new SplunkHecClient({ maxBatchSize: 100, flushIntervalMs: 500, maxRetries: 3 });
  const INCIDENT_ID = 9001; // fixed demo incident ID
  const BASE_TIME = Date.now() - 4 * 60 * 60 * 1000; // 4 hours ago

  const allEvents: HecEvent[] = [
    ...genStage1Recon(BASE_TIME, INCIDENT_ID),
    ...genStage2InitialAccess(BASE_TIME, INCIDENT_ID),
    ...genStage3C2(BASE_TIME, INCIDENT_ID),
    ...genStage4LateralMovement(BASE_TIME, INCIDENT_ID),
    ...genStage5Encryption(BASE_TIME, INCIDENT_ID),
  ];

  console.log(`📦 Generated ${allEvents.length} synthetic events across 5 attack stages`);

  // POST to Splunk HEC in batches
  await hec.sendBatch(allEvents);
  await hec.flush();
  console.log("✅ Events sent to Splunk HEC (or logged in mock mode)\n");

  console.log("\n🎉 Demo seed complete!");
  console.log(`   Incident ID: ${INCIDENT_ID}`);
  console.log(`   Events: ${allEvents.length}`);
  console.log("   Expected: timeline shows 5 stages, risk score ≥ 85, enrichment_data has IOC list");
  console.log("   Navigate to Incidents → Incident #9001 to see the full demo");
}

main().catch((err) => {
  console.error("Seed failed:", err);
  process.exit(1);
});
