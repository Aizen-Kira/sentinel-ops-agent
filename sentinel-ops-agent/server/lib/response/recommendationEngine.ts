// lib/response/recommendationEngine.ts
import type { EnrichmentResult } from "../agents/investigationTypes";
import type { ResponseAction } from "@shared/splunkTypes";

export type { ResponseAction };

export const ACTION_LIBRARY: ResponseAction[] = [
  { id: "isolate-host", title: "Isolate Compromised Hosts", description: "Network-quarantine all hosts identified as compromised via EDR or firewall ACL.", mitreTechniqueId: "T1219", priority: 1, estimatedTimeMinutes: 15, requiresApproval: true, automated: true, category: "containment" },
  { id: "reset-creds", title: "Force Password Reset — Affected Accounts", description: "Immediately reset credentials for all user accounts identified in IOC list.", mitreTechniqueId: "T1078", priority: 1, estimatedTimeMinutes: 30, requiresApproval: true, automated: false, category: "containment" },
  { id: "block-c2-ips", title: "Block C2 IP Addresses at Firewall", description: "Add all identified C2 IPs to perimeter firewall deny list.", mitreTechniqueId: "T1071.001", priority: 1, estimatedTimeMinutes: 10, requiresApproval: false, automated: true, category: "containment" },
  { id: "preserve-forensics", title: "Preserve Forensic Evidence", description: "Snapshot disk images of affected systems before remediation begins.", mitreTechniqueId: "T1005", priority: 2, estimatedTimeMinutes: 60, requiresApproval: false, automated: false, category: "containment" },
  { id: "remove-persistence", title: "Remove Persistence Mechanisms", description: "Scan and remove scheduled tasks, registry run keys, and startup scripts created by threat actor.", mitreTechniqueId: "T1053.005", priority: 2, estimatedTimeMinutes: 45, requiresApproval: true, automated: false, category: "eradication" },
  { id: "patch-exploited-vuln", title: "Patch Exploited Vulnerability", description: "Apply security patches to all systems exploited during initial access phase.", mitreTechniqueId: "T1190", priority: 2, estimatedTimeMinutes: 120, requiresApproval: true, automated: false, category: "eradication" },
  { id: "restore-from-backup", title: "Restore Encrypted Files from Backup", description: "Restore all .locked files from last known-good backup. Verify backup integrity first.", mitreTechniqueId: "T1486", priority: 3, estimatedTimeMinutes: 240, requiresApproval: true, automated: false, category: "recovery" },
  { id: "deploy-edr", title: "Deploy Enhanced EDR Rules", description: "Push updated detection signatures to EDR agents covering all observed TTPs.", mitreTechniqueId: "T1562.001", priority: 3, estimatedTimeMinutes: 30, requiresApproval: false, automated: true, category: "detection" },
  { id: "enable-mfa", title: "Enforce MFA on All VPN/RDP Access", description: "Immediately enable MFA for all remote access methods to prevent re-entry.", mitreTechniqueId: "T1021.001", priority: 2, estimatedTimeMinutes: 90, requiresApproval: true, automated: false, category: "containment" },
  { id: "threat-hunt", title: "Launch Proactive Threat Hunt", description: "Search environment for additional indicators from same threat group using Splunk SPL.", mitreTechniqueId: "T1595", priority: 3, estimatedTimeMinutes: 180, requiresApproval: false, automated: false, category: "detection" },
];

export function getRecommendations(enrichment: EnrichmentResult, riskScore: number): ResponseAction[] {
  const actions = [...ACTION_LIBRARY];

  // Boost priority for actions matching observed MITRE techniques
  const scored = actions.map((action) => {
    let boost = 0;
    if (enrichment.mitreAttackIds.some((id) => action.mitreTechniqueId.startsWith(id.split(".")[0]!))) boost += 2;
    if (riskScore >= 75) boost += 1; // critical incidents get more actions prioritized
    if (enrichment.requiresEscalation && action.category === "containment") boost += 2;
    return { ...action, priority: Math.max(1, action.priority - boost) as ResponseAction["priority"] };
  });

  return scored.sort((a, b) => a.priority - b.priority).slice(0, 8); // top 8
}
