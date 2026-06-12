# SentinelMCP API Reference

## Model Context Protocol (MCP) Tools

SentinelMCP exposes 16 tools via the FastMCP server. These can be categorized into four domains:

### Disk Parsers
- `mftdump`: Parse MFT to track file creation, modification, and deletion.
- `pecmd`: Parse Prefetch files for execution tracking.
- `amcacheparser`: Parse Amcache for file execution and SHA1 hashes.
- `shimcache`: Extract Shimcache (AppCompatCache) persistence details.
- `reglookup`: Query specific registry keys (Run keys, Services).
- `fls`: Analyze deleted file entries.
- `evtxdump`: Parse Windows Event Logs (Security, System, Sysmon).

### Memory Parsers
- `vol3_pslist`: Enumerate running processes.
- `vol3_netscan`: Identify active network connections.
- `vol3_malfind`: Detect injected or unbacked memory regions.
- `vol3_cmdline`: Extract process command lines.

### Network Parsers
- `tshark_conversations`: Summarize TCP/UDP conversations.
- `tshark_dns`: Extract DNS queries and responses.
- `tshark_http`: Extract HTTP requests (Method, Host, URI, User-Agent).

### Correlation Tools
- `correlate_disk_memory`: Map processes found in memory to disk artifacts.
- `timeline_gaps`: Identify missing periods in chronological events.
- `build_super_timeline`: Merge Disk, Memory, and Network events into a unified chronological array.
- `yara_scan`: Scan specific paths for known malicious signatures.

## Data Models (`shared/models.py`)
- `Finding`: A core unit of analysis describing an anomaly or malicious activity.
- `Gap`: A missing piece of evidence identified by the deterministic evaluator.
- `IOC`: An extracted Indicator of Compromise.
- `Case`: Defines the scope of the triage session (Disk, Memory, PCAP).
