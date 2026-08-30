from __future__ import annotations

import argparse
import sys

from .audit import run_audit
from .config import load_configuration
from .model import ReportWriteError
from .reporting import render_json, render_text


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="conformrepo")
    subparsers = parser.add_subparsers(dest="command", required=True)
    check = subparsers.add_parser("check")
    check.add_argument("--config", required=True)
    args = parser.parse_args(argv)
    try:
        result = run_audit(args.config, write_report=True)
        config, _ = load_configuration(args.config)
        renderer = render_text if config.report.get("format") == "text" else render_json
        if config.report.get("destination", "stdout") == "stdout":
            sys.stdout.write(renderer(result))
        elif not result.scan_started:
            for finding in result.findings:
                if finding.code == "UNSAFE_REPORT_DESTINATION":
                    sys.stderr.write(f"{finding.code}: {finding.message}\n")
                    break
        return result.exit_code
    except ReportWriteError as exc:
        sys.stderr.write(f"tool/write failure: {exc}\n")
        return 3
    except (OSError, ValueError) as exc:
        sys.stderr.write(f"configuration error: {exc}\n")
        return 2
    except Exception as exc:  # unexpected failures retain the distinct tool outcome
        sys.stderr.write(f"tool failure: {exc}\n")
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
