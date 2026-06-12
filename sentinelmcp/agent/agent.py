"""CLI entry point for SentinelMCP.

Usage:
    sentinelmcp --disk /evidence/disk.E01 --memory /evidence/mem.dmp \
                --pcap /evidence/capture.pcap --description "Lateral movement"
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
import uuid

from agent.loop import run_correction_loop
from agent.reporter import generate_report
from shared.models import Case

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)


def _build_case(args: argparse.Namespace) -> Case:
    return Case(
        id=str(uuid.uuid4()),
        disk_path=args.disk or "",
        memory_path=args.memory or "",
        pcap_path=args.pcap or "",
        description=args.description or "",
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="sentinelmcp",
        description="AI-powered DFIR triage agent",
    )
    parser.add_argument("--disk", metavar="PATH", help="Disk image path")
    parser.add_argument("--memory", metavar="PATH", help="Memory dump path")
    parser.add_argument("--pcap", metavar="PATH", help="PCAP capture path")
    parser.add_argument("--description", metavar="TEXT", help="Case description")
    parser.add_argument(
        "--max-iter", type=int, default=8, metavar="N",
        help="Maximum self-correction iterations (default: 8)",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="Write HTML report to this file (default: stdout JSON)",
    )
    parser.add_argument("--json", action="store_true", help="Output raw JSON instead of HTML")
    args = parser.parse_args()

    case = _build_case(args)
    logger.info("Starting triage for case %s", case.id)

    result = run_correction_loop(case, max_iter=args.max_iter)

    if args.json:
        output = json.dumps(
            {
                "case_id": result.case_id,
                "findings": [
                    {
                        "id": f.id,
                        "title": f.title,
                        "status": f.status.value,
                        "severity": f.severity,
                        "source_tools": f.source_tools,
                        "evidence": f.evidence,
                        "ioc_type": f.ioc_type,
                        "ioc_value": f.ioc_value,
                    }
                    for f in result.findings
                ],
                "iterations": len(result.iterations),
            },
            indent=2,
        )
        print(output)
    else:
        html = generate_report(result, case)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(html)
            logger.info("Report written to %s", args.output)
        else:
            print(html)

    confirmed = sum(1 for f in result.findings if f.status.value == "CONFIRMED")
    logger.info(
        "Triage complete — %d findings (%d CONFIRMED) in %d iteration(s)",
        len(result.findings),
        confirmed,
        len(result.iterations),
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
