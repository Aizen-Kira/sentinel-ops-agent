# Benchmark Methodology

SentinelMCP includes a comprehensive benchmark suite designed to evaluate the triage loop's accuracy and robustness against varied attack scenarios.

## Metrics
The benchmark system (`benchmark/scorer.py`) evaluates the `TriageResult` using several key metrics:
1. **Precision & Recall**: Calculated against the `CONFIRMED` findings to measure direct evidence matching.
2. **Inferred Recall**: Measures the `INFERRED` findings to ensure the LLM implies the right IOCs even if hard evidence is missing.
3. **Hallucination Rate**: Percentage of findings that falsely identify known clean entities as malicious.
4. **IOC Precision & Recall**: Accuracy of the deterministic regex-based IOC extraction framework.
5. **Timeline Ordering Accuracy**: Accuracy of the super-timeline chronological sequence reconstruction.

## Benchmark Scenarios
- `clean_baseline`: A system with normal activity to test for false positives.
- `credential_theft`: Mimikatz execution and LSASS dumping.
- `data_exfiltration`: Data staging and outbound transfers.
- `insider_threat`: Unauthorized data access and archival.
- `lateral_movement`: Pass-the-hash and PsExec execution.
- `living_off_the_land`: Abuse of native binaries (PowerShell, WMIC).
- `ransomware`: Execution, shadow copy deletion, and file encryption.
- `supply_chain`: Trojanized updater execution and backdoor persistence.

## Running Benchmarks
Use the testing harness to validate the agent against the benchmark suite:
```bash
python -m pytest tests/test_benchmark_scorer.py -v
```
