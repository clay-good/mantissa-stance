"""
Interactive shell (REPL) for Mantissa Stance.

Provides an interactive command-line environment for exploring
findings, assets, and running queries without repeated CLI invocations.
"""

from __future__ import annotations

import argparse
import cmd
import json
import readline
import shlex
import sys
from datetime import datetime
from typing import Any

from stance import __version__


class StanceShell(cmd.Cmd):
    """
    Interactive shell for Stance CSPM.

    Provides commands for exploring findings, assets, policies,
    and running queries in an interactive session.
    """

    intro = f"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║  Mantissa Stance Interactive Shell v{__version__:<43}║
║  Type 'help' for available commands, 'quit' to exit.                         ║
╚═══════════════════════════════════════════════════════════════════════════════╝
"""
    prompt = "stance> "

    def __init__(
        self,
        storage_type: str = "local",
        verbose: bool = False,
        llm_provider: str | None = None,
    ):
        """
        Initialize the shell.

        Args:
            storage_type: Storage backend to use
            verbose: Enable verbose output
            llm_provider: LLM provider for natural language queries
        """
        super().__init__()
        self._storage_type = storage_type
        self._verbose = verbose
        self._llm_provider = llm_provider
        self._storage = None
        self._last_results: list[dict[str, Any]] = []
        self._history: list[str] = []
        self._context: dict[str, Any] = {}

        # Configure readline for history
        try:
            readline.read_history_file(".stance_history")
        except FileNotFoundError:
            pass

    @property
    def storage(self):
        """Lazy-load storage backend."""
        if self._storage is None:
            from stance.storage import get_storage
            self._storage = get_storage(self._storage_type)
        return self._storage

    def precmd(self, line: str) -> str:
        """Record command in history before execution."""
        if line.strip():
            self._history.append(line)
        return line

    def postcmd(self, stop: bool, line: str) -> bool:
        """Save history after each command."""
        try:
            readline.write_history_file(".stance_history")
        except Exception:
            pass
        return stop

    def default(self, line: str) -> None:
        """Handle unknown commands as potential queries."""
        # Check if it looks like SQL
        normalized = " ".join(line.split()).upper()
        if normalized.startswith("SELECT"):
            self.do_sql(line)
        else:
            print(f"Unknown command: {line.split()[0]}")
            print("Type 'help' for available commands.")

    def emptyline(self) -> bool:
        """Don't repeat last command on empty line."""
        return False

    # =========================================================================
    # Core Commands
    # =========================================================================

    def do_quit(self, arg: str) -> bool:
        """Exit the shell."""
        print("Goodbye!")
        return True

    def do_exit(self, arg: str) -> bool:
        """Exit the shell (alias for quit)."""
        return self.do_quit(arg)

    def do_EOF(self, arg: str) -> bool:
        """Exit on Ctrl+D."""
        print()
        return self.do_quit(arg)

    def do_version(self, arg: str) -> None:
        """Show version information."""
        print(f"Mantissa Stance v{__version__}")

    def do_clear(self, arg: str) -> None:
        """Clear the screen."""
        print("\033[2J\033[H", end="")

    # =========================================================================
    # Findings Commands
    # =========================================================================

    def do_findings(self, arg: str) -> None:
        """
        List or search findings.

        Usage:
            findings              - List recent findings
            findings --severity critical  - Filter by severity
            findings --limit 10   - Limit results
            findings --json       - Output as JSON
        """
        try:
            args = self._parse_findings_args(arg)
            self._show_findings(args)
        except Exception as e:
            print(f"Error: {e}")

    def _parse_findings_args(self, arg: str) -> argparse.Namespace:
        """Parse findings command arguments."""
        parser = argparse.ArgumentParser(prog="findings", add_help=False)
        parser.add_argument("--severity", "-s", help="Filter by severity")
        parser.add_argument("--policy", "-p", help="Filter by policy ID")
        parser.add_argument("--asset", "-a", help="Filter by asset ID")
        parser.add_argument("--limit", "-l", type=int, default=20, help="Limit results")
        parser.add_argument("--json", "-j", action="store_true", help="JSON output")
        parser.add_argument("--help", "-h", action="store_true", help="Show help")

        try:
            parts = shlex.split(arg) if arg else []
        except ValueError:
            parts = arg.split() if arg else []

        args = parser.parse_args(parts)
        if args.help:
            parser.print_help()
            raise SystemExit()
        return args

    def _show_findings(self, args: argparse.Namespace) -> None:
        """Display findings based on arguments."""
        # Build SQL query
        conditions = []
        if args.severity:
            conditions.append(f"severity = '{args.severity}'")
        if args.policy:
            conditions.append(f"rule_id LIKE '%{args.policy}%'")
        if args.asset:
            conditions.append(f"asset_id LIKE '%{args.asset}%'")

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM findings WHERE {where} ORDER BY severity LIMIT {args.limit}"

        results = self.storage.query_findings(sql)
        self._last_results = results

        if not results:
            print("No findings found.")
            return

        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            self._print_findings_table(results)

    def _print_findings_table(self, findings: list[dict]) -> None:
        """Print findings in table format."""
        print(f"\n{'ID':<40} {'Severity':<10} {'Policy':<25} {'Asset':<30}")
        print("-" * 105)
        for f in findings:
            fid = str(f.get("id", ""))[:38]
            sev = str(f.get("severity", ""))[:8]
            policy = str(f.get("rule_id", ""))[:23]
            asset = str(f.get("asset_id", ""))[:28]
            print(f"{fid:<40} {sev:<10} {policy:<25} {asset:<30}")
        print(f"\nTotal: {len(findings)} findings")

    def do_finding(self, arg: str) -> None:
        """
        Show details of a specific finding.

        Usage:
            finding <id>          - Show finding details
            finding --json <id>   - Output as JSON
        """
        parts = shlex.split(arg) if arg else []
        json_output = "--json" in parts or "-j" in parts
        parts = [p for p in parts if p not in ("--json", "-j")]

        if not parts:
            print("Usage: finding <finding_id>")
            return

        finding_id = parts[0]

        try:
            sql = f"SELECT * FROM findings WHERE id = '{finding_id}'"
            results = self.storage.query_findings(sql)

            if not results:
                print(f"Finding not found: {finding_id}")
                return

            finding = results[0]
            if json_output:
                print(json.dumps(finding, indent=2, default=str))
            else:
                self._print_finding_detail(finding)
        except Exception as e:
            print(f"Error: {e}")

    def _print_finding_detail(self, finding: dict) -> None:
        """Print detailed finding information."""
        print("\n" + "=" * 60)
        print(f"Finding: {finding.get('id', 'N/A')}")
        print("=" * 60)
        print(f"Severity:    {finding.get('severity', 'N/A')}")
        print(f"Policy:      {finding.get('rule_id', 'N/A')}")
        print(f"Asset:       {finding.get('asset_id', 'N/A')}")
        print(f"Asset Type:  {finding.get('asset_type', 'N/A')}")
        print(f"Status:      {finding.get('status', 'N/A')}")
        if finding.get("description"):
            print(f"\nDescription:\n  {finding['description']}")
        if finding.get("remediation"):
            print(f"\nRemediation:\n  {finding['remediation']}")
        print()

    # =========================================================================
    # Assets Commands
    # =========================================================================

    def do_assets(self, arg: str) -> None:
        """
        List or search assets.

        Usage:
            assets                - List recent assets
            assets --type ec2     - Filter by type
            assets --limit 10     - Limit results
            assets --json         - Output as JSON
        """
        try:
            args = self._parse_assets_args(arg)
            self._show_assets(args)
        except Exception as e:
            print(f"Error: {e}")

    def _parse_assets_args(self, arg: str) -> argparse.Namespace:
        """Parse assets command arguments."""
        parser = argparse.ArgumentParser(prog="assets", add_help=False)
        parser.add_argument("--type", "-t", help="Filter by asset type")
        parser.add_argument("--id", "-i", help="Filter by asset ID pattern")
        parser.add_argument("--limit", "-l", type=int, default=20, help="Limit results")
        parser.add_argument("--json", "-j", action="store_true", help="JSON output")
        parser.add_argument("--help", "-h", action="store_true", help="Show help")

        try:
            parts = shlex.split(arg) if arg else []
        except ValueError:
            parts = arg.split() if arg else []

        args = parser.parse_args(parts)
        if args.help:
            parser.print_help()
            raise SystemExit()
        return args

    def _show_assets(self, args: argparse.Namespace) -> None:
        """Display assets based on arguments."""
        conditions = []
        if args.type:
            conditions.append(f"asset_type LIKE '%{args.type}%'")
        if args.id:
            conditions.append(f"id LIKE '%{args.id}%'")

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM assets WHERE {where} LIMIT {args.limit}"

        results = self.storage.query_assets(sql)
        self._last_results = results

        if not results:
            print("No assets found.")
            return

        if args.json:
            print(json.dumps(results, indent=2, default=str))
        else:
            self._print_assets_table(results)

    def _print_assets_table(self, assets: list[dict]) -> None:
        """Print assets in table format."""
        print(f"\n{'ID':<50} {'Type':<25} {'Region':<15}")
        print("-" * 90)
        for a in assets:
            aid = str(a.get("id", ""))[:48]
            atype = str(a.get("asset_type", ""))[:23]
            region = str(a.get("region", ""))[:13]
            print(f"{aid:<50} {atype:<25} {region:<15}")
        print(f"\nTotal: {len(assets)} assets")

    def do_asset(self, arg: str) -> None:
        """
        Show details of a specific asset.

        Usage:
            asset <id>            - Show asset details
            asset --json <id>     - Output as JSON
        """
        parts = shlex.split(arg) if arg else []
        json_output = "--json" in parts or "-j" in parts
        parts = [p for p in parts if p not in ("--json", "-j")]

        if not parts:
            print("Usage: asset <asset_id>")
            return

        asset_id = parts[0]

        try:
            sql = f"SELECT * FROM assets WHERE id = '{asset_id}'"
            results = self.storage.query_assets(sql)

            if not results:
                print(f"Asset not found: {asset_id}")
                return

            asset = results[0]
            if json_output:
                print(json.dumps(asset, indent=2, default=str))
            else:
                self._print_asset_detail(asset)
        except Exception as e:
            print(f"Error: {e}")

    def _print_asset_detail(self, asset: dict) -> None:
        """Print detailed asset information."""
        print("\n" + "=" * 60)
        print(f"Asset: {asset.get('id', 'N/A')}")
        print("=" * 60)
        print(f"Type:        {asset.get('asset_type', 'N/A')}")
        print(f"Region:      {asset.get('region', 'N/A')}")
        print(f"Account:     {asset.get('account_id', 'N/A')}")
        if asset.get("tags"):
            print(f"\nTags:")
            tags = asset["tags"]
            if isinstance(tags, str):
                try:
                    tags = json.loads(tags)
                except json.JSONDecodeError:
                    pass
            if isinstance(tags, dict):
                for k, v in tags.items():
                    print(f"  {k}: {v}")
        print()

    # =========================================================================
    # Query Commands
    # =========================================================================

    def do_sql(self, arg: str) -> None:
        """
        Execute a SQL query.

        Usage:
            sql SELECT * FROM findings WHERE severity = 'critical'
            SELECT * FROM assets WHERE asset_type LIKE '%s3%'
        """
        if not arg:
            print("Usage: sql <SELECT statement>")
            return

        try:
            sql = arg.strip()
            if not sql.upper().startswith("SELECT"):
                print("Error: Only SELECT queries are allowed")
                return

            # Determine table
            sql_upper = sql.upper()
            if "FROM ASSETS" in sql_upper:
                results = self.storage.query_assets(sql)
            else:
                results = self.storage.query_findings(sql)

            self._last_results = results

            if not results:
                print("No results found.")
                return

            print(json.dumps(results, indent=2, default=str))
        except Exception as e:
            print(f"Query error: {e}")

    def do_query(self, arg: str) -> None:
        """
        Execute a natural language query (requires LLM).

        Usage:
            query Show me all critical findings
            query How many S3 buckets have public access?
        """
        if not arg:
            print("Usage: query <natural language question>")
            return

        if not self._llm_provider:
            print("Error: LLM provider not configured. Use --llm-provider when starting shell.")
            return

        try:
            from stance.llm import get_llm_provider, QueryGenerator

            provider = get_llm_provider(self._llm_provider)
            generator = QueryGenerator(provider)
            result = generator.generate_query(arg)

            if not result.is_valid:
                print("Error: Could not generate valid query")
                for error in result.validation_errors:
                    print(f"  - {error}")
                return

            if self._verbose:
                print(f"Generated SQL: {result.sql}")
                print()

            # Execute the generated query
            self.do_sql(result.sql)
        except Exception as e:
            print(f"Query error: {e}")

    # =========================================================================
    # Policy Commands
    # =========================================================================

    def do_policies(self, arg: str) -> None:
        """
        List available policies.

        Usage:
            policies              - List all policies
            policies --severity critical  - Filter by severity
            policies --limit 20   - Limit results
        """
        try:
            from stance.engine import PolicyLoader

            loader = PolicyLoader()
            policies = loader.load_all()

            # Parse arguments
            parts = shlex.split(arg) if arg else []
            severity_filter = None
            limit = 50

            for i, p in enumerate(parts):
                if p in ("--severity", "-s") and i + 1 < len(parts):
                    severity_filter = parts[i + 1].lower()
                elif p in ("--limit", "-l") and i + 1 < len(parts):
                    limit = int(parts[i + 1])

            # Filter and display
            filtered = policies
            if severity_filter:
                filtered = [p for p in policies if p.severity.value == severity_filter]

            print(f"\n{'ID':<30} {'Severity':<10} {'Name':<40}")
            print("-" * 80)
            for p in filtered[:limit]:
                print(f"{p.id:<30} {p.severity.value:<10} {p.name[:38]:<40}")
            print(f"\nTotal: {len(filtered)} policies (showing {min(len(filtered), limit)})")
        except Exception as e:
            print(f"Error loading policies: {e}")

    def do_policy(self, arg: str) -> None:
        """
        Show details of a specific policy.

        Usage:
            policy <policy_id>
        """
        if not arg:
            print("Usage: policy <policy_id>")
            return

        try:
            from stance.engine import PolicyLoader

            policy_id = arg.strip()
            loader = PolicyLoader()
            policies = loader.load_all()

            policy = next((p for p in policies if p.id == policy_id), None)
            if not policy:
                print(f"Policy not found: {policy_id}")
                return

            print("\n" + "=" * 60)
            print(f"Policy: {policy.id}")
            print("=" * 60)
            print(f"Name:        {policy.name}")
            print(f"Severity:    {policy.severity.value}")
            print(f"Type:        {policy.resource_type}")
            print(f"Enabled:     {policy.enabled}")
            if policy.description:
                print(f"\nDescription:\n  {policy.description.strip()}")
            if policy.remediation:
                print(f"\nRemediation:\n  {policy.remediation.guidance[:200]}...")
            if policy.tags:
                print(f"\nTags: {', '.join(policy.tags)}")
            print()
        except Exception as e:
            print(f"Error: {e}")

    # =========================================================================
    # Summary Commands
    # =========================================================================

    def do_summary(self, arg: str) -> None:
        """
        Show summary of current posture.

        Usage:
            summary               - Show findings summary
            summary --json        - Output as JSON
        """
        try:
            json_output = "--json" in arg or "-j" in arg

            # Get findings counts by severity
            sql = """
            SELECT severity, COUNT(*) as count
            FROM findings
            GROUP BY severity
            """
            severity_results = self.storage.query_findings(sql)

            # Get total assets
            assets_sql = "SELECT COUNT(*) as count FROM assets"
            assets_results = self.storage.query_assets(assets_sql)

            summary = {
                "timestamp": datetime.utcnow().isoformat(),
                "total_assets": assets_results[0]["count"] if assets_results else 0,
                "findings_by_severity": {
                    r["severity"]: r["count"] for r in severity_results
                },
                "total_findings": sum(r["count"] for r in severity_results),
            }

            if json_output:
                print(json.dumps(summary, indent=2))
            else:
                print("\n" + "=" * 40)
                print("POSTURE SUMMARY")
                print("=" * 40)
                print(f"Generated: {summary['timestamp']}")
                print(f"Total Assets: {summary['total_assets']}")
                print(f"Total Findings: {summary['total_findings']}")
                print("\nFindings by Severity:")
                for sev in ["critical", "high", "medium", "low", "info"]:
                    count = summary["findings_by_severity"].get(sev, 0)
                    if count:
                        print(f"  {sev.upper():<10}: {count}")
                print()
        except Exception as e:
            print(f"Error generating summary: {e}")

    # =========================================================================
    # Utility Commands
    # =========================================================================

    def do_last(self, arg: str) -> None:
        """
        Show last query results.

        Usage:
            last                  - Show last results
            last --json           - Output as JSON
            last 5                - Show first 5 results
        """
        if not self._last_results:
            print("No previous results.")
            return

        json_output = "--json" in arg or "-j" in arg
        limit = len(self._last_results)

        parts = arg.replace("--json", "").replace("-j", "").split()
        if parts:
            try:
                limit = int(parts[0])
            except ValueError:
                pass

        results = self._last_results[:limit]
        if json_output:
            print(json.dumps(results, indent=2, default=str))
        else:
            print(json.dumps(results, indent=2, default=str))

    def do_count(self, arg: str) -> None:
        """Show count of last query results."""
        print(f"Last results count: {len(self._last_results)}")

    def do_history(self, arg: str) -> None:
        """Show command history."""
        limit = 20
        if arg:
            try:
                limit = int(arg)
            except ValueError:
                pass

        history = self._history[-limit:]
        for i, cmd in enumerate(history, 1):
            print(f"  {i}. {cmd}")

    def do_set(self, arg: str) -> None:
        """
        Set shell configuration.

        Usage:
            set verbose on        - Enable verbose output
            set verbose off       - Disable verbose output
            set llm <provider>    - Set LLM provider
        """
        parts = shlex.split(arg) if arg else []
        if len(parts) < 2:
            print("Current settings:")
            print(f"  verbose: {'on' if self._verbose else 'off'}")
            print(f"  llm_provider: {self._llm_provider or 'not set'}")
            print(f"  storage: {self._storage_type}")
            return

        key, value = parts[0].lower(), parts[1]
        if key == "verbose":
            self._verbose = value.lower() in ("on", "true", "1", "yes")
            print(f"Verbose: {'on' if self._verbose else 'off'}")
        elif key == "llm":
            self._llm_provider = value
            print(f"LLM provider: {value}")
        else:
            print(f"Unknown setting: {key}")

    def help_commands(self) -> None:
        """Show available commands."""
        print("""
Available Commands:
==================

Navigation:
  findings [options]    - List findings (--severity, --limit, --json)
  finding <id>          - Show finding details
  assets [options]      - List assets (--type, --limit, --json)
  asset <id>            - Show asset details
  policies [options]    - List policies (--severity, --limit)
  policy <id>           - Show policy details

Queries:
  sql <query>           - Execute SQL query
  query <question>      - Natural language query (requires LLM)
  SELECT ...            - Direct SQL (auto-detected)

Summary:
  summary               - Show posture summary

Utilities:
  last [n]              - Show last query results
  count                 - Count of last results
  history [n]           - Show command history
  set <key> <value>     - Configure shell settings
  clear                 - Clear screen
  version               - Show version

Exit:
  quit, exit, Ctrl+D    - Exit shell
""")


def cmd_shell(args: argparse.Namespace) -> int:
    """
    Launch interactive shell.

    Args:
        args: Command-line arguments

    Returns:
        Exit code
    """
    storage_type = getattr(args, "storage", "local")
    verbose = getattr(args, "verbose", 0) > 0
    llm_provider = getattr(args, "llm_provider", None)

    shell = StanceShell(
        storage_type=storage_type,
        verbose=verbose,
        llm_provider=llm_provider,
    )

    try:
        shell.cmdloop()
        return 0
    except KeyboardInterrupt:
        print("\nInterrupted. Goodbye!")
        return 0
    except Exception as e:
        print(f"Shell error: {e}")
        return 1
