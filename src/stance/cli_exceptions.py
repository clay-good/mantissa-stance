"""
CLI commands for Policy Exceptions management.

Provides command-line interface for managing policy exceptions,
suppressions, false positives, risk acceptances, and compensating controls.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from typing import Any

from stance.exceptions import (
    ExceptionManager,
    ExceptionType,
    ExceptionScope,
    ExceptionStatus,
    PolicyException,
    get_exception_manager,
)


def _format_exception_table(exceptions: list[PolicyException]) -> str:
    """Format exceptions as a table."""
    if not exceptions:
        return "No exceptions found."

    # Calculate column widths
    id_width = min(max(len(e.id[:8]) for e in exceptions), 8)
    type_width = max(len(e.exception_type.value) for e in exceptions)
    scope_width = max(len(e.scope.value) for e in exceptions)
    status_width = max(len(e.status.value) for e in exceptions)

    # Build table
    lines = []
    header = f"{'ID':<{id_width}}  {'Type':<{type_width}}  {'Scope':<{scope_width}}  {'Status':<{status_width}}  {'Expiry':<12}  Reason"
    lines.append(header)
    lines.append("-" * len(header))

    for exc in sorted(exceptions, key=lambda e: e.created_at, reverse=True):
        exc_id = exc.id[:8]
        expiry = "Never"
        if exc.expires_at:
            days = exc.days_until_expiry
            if days is not None:
                if days == 0:
                    expiry = "Today"
                elif days < 0:
                    expiry = "Expired"
                else:
                    expiry = f"{days}d"

        reason = exc.reason[:40]
        if len(exc.reason) > 40:
            reason += "..."

        line = f"{exc_id:<{id_width}}  {exc.exception_type.value:<{type_width}}  {exc.scope.value:<{scope_width}}  {exc.status.value:<{status_width}}  {expiry:<12}  {reason}"
        lines.append(line)

    return "\n".join(lines)


def _format_exception_detail(exc: PolicyException, verbose: bool = False) -> str:
    """Format exception details."""
    lines = []
    lines.append(f"Exception ID: {exc.id}")
    lines.append(f"Type: {exc.exception_type.value}")
    lines.append(f"Scope: {exc.scope.value}")
    lines.append(f"Status: {exc.status.value}")
    lines.append(f"Reason: {exc.reason}")
    lines.append(f"Created By: {exc.created_by or 'Unknown'}")
    lines.append(f"Created At: {exc.created_at.isoformat()}")

    if exc.approved_by:
        lines.append(f"Approved By: {exc.approved_by}")

    if exc.expires_at:
        lines.append(f"Expires At: {exc.expires_at.isoformat()}")
        days = exc.days_until_expiry
        if days is not None:
            lines.append(f"Days Until Expiry: {days}")

    lines.append(f"Is Active: {exc.is_active}")

    if exc.policy_id:
        lines.append(f"Policy ID: {exc.policy_id}")
    if exc.asset_id:
        lines.append(f"Asset ID: {exc.asset_id}")
    if exc.finding_id:
        lines.append(f"Finding ID: {exc.finding_id}")
    if exc.resource_type:
        lines.append(f"Resource Type: {exc.resource_type}")
    if exc.account_id:
        lines.append(f"Account ID: {exc.account_id}")
    if exc.tag_key:
        lines.append(f"Tag: {exc.tag_key}={exc.tag_value or '*'}")
    if exc.jira_ticket:
        lines.append(f"Jira Ticket: {exc.jira_ticket}")

    if verbose:
        if exc.conditions:
            lines.append(f"Conditions: {json.dumps(exc.conditions, indent=2)}")
        if exc.metadata:
            lines.append(f"Metadata: {json.dumps(exc.metadata, indent=2)}")
        if exc.notes:
            lines.append(f"Notes: {exc.notes}")

    return "\n".join(lines)


def cmd_exceptions(args: argparse.Namespace) -> int:
    """Handle exceptions commands."""
    action = getattr(args, 'exceptions_action', None)

    if action is None:
        print("Usage: stance exceptions <command>")
        print("\nCommands:")
        print("  list         List all exceptions")
        print("  show         Show exception details")
        print("  create       Create a new exception")
        print("  suppress     Create a suppression for a finding/policy/asset")
        print("  false-positive  Mark finding as false positive")
        print("  accept-risk  Create a risk acceptance")
        print("  revoke       Revoke an exception")
        print("  delete       Delete an exception")
        print("  expire       Expire outdated exceptions")
        print("  types        List exception types")
        print("  scopes       List exception scopes")
        print("  status       Show exceptions module status")
        return 0

    handlers = {
        'list': _handle_exceptions_list,
        'show': _handle_exceptions_show,
        'create': _handle_exceptions_create,
        'suppress': _handle_exceptions_suppress,
        'false-positive': _handle_exceptions_false_positive,
        'accept-risk': _handle_exceptions_accept_risk,
        'revoke': _handle_exceptions_revoke,
        'delete': _handle_exceptions_delete,
        'expire': _handle_exceptions_expire,
        'types': _handle_exceptions_types,
        'scopes': _handle_exceptions_scopes,
        'status': _handle_exceptions_status,
    }

    handler = handlers.get(action)
    if handler:
        return handler(args)

    print(f"Unknown exceptions action: {action}")
    return 1


def _handle_exceptions_list(args: argparse.Namespace) -> int:
    """List all exceptions."""
    manager = get_exception_manager()
    output_format = getattr(args, 'format', 'table')
    status_filter = getattr(args, 'status', None)
    type_filter = getattr(args, 'type', None)
    scope_filter = getattr(args, 'scope', None)
    include_expired = getattr(args, 'include_expired', False)
    active_only = getattr(args, 'active', False)

    try:
        # Parse filters
        status = ExceptionStatus(status_filter) if status_filter else None
        exc_type = ExceptionType(type_filter) if type_filter else None
        scope = ExceptionScope(scope_filter) if scope_filter else None

        if active_only:
            exceptions = manager.get_active_exceptions()
        else:
            exceptions = manager.list_exceptions(
                status=status,
                exception_type=exc_type,
                scope=scope,
                include_expired=include_expired,
            )

        if output_format == 'json':
            print(json.dumps([e.to_dict() for e in exceptions], indent=2))
        else:
            print(_format_exception_table(exceptions))
            print(f"\nTotal: {len(exceptions)} exception(s)")

        return 0

    except ValueError as e:
        print(f"Invalid filter value: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error listing exceptions: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_show(args: argparse.Namespace) -> int:
    """Show exception details."""
    manager = get_exception_manager()
    exception_id = getattr(args, 'exception_id', None)
    output_format = getattr(args, 'format', 'text')
    verbose = getattr(args, 'verbose', False)

    if not exception_id:
        print("Error: Exception ID is required", file=sys.stderr)
        return 1

    try:
        # Try to find by ID (support partial IDs)
        all_exceptions = manager.list_exceptions(include_expired=True)
        matches = [e for e in all_exceptions if e.id.startswith(exception_id)]

        if not matches:
            print(f"Exception not found: {exception_id}", file=sys.stderr)
            return 1

        if len(matches) > 1:
            print(f"Multiple exceptions match '{exception_id}':", file=sys.stderr)
            for e in matches:
                print(f"  {e.id[:12]} ({e.exception_type.value})")
            return 1

        exc = matches[0]

        if output_format == 'json':
            print(json.dumps(exc.to_dict(), indent=2))
        else:
            print(_format_exception_detail(exc, verbose=verbose))

        return 0

    except Exception as e:
        print(f"Error showing exception: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_create(args: argparse.Namespace) -> int:
    """Create a new exception."""
    manager = get_exception_manager()
    exc_type = getattr(args, 'type', 'suppression')
    scope = getattr(args, 'scope', 'finding')
    reason = getattr(args, 'reason', '')
    created_by = getattr(args, 'created_by', 'cli')
    policy_id = getattr(args, 'policy', None)
    asset_id = getattr(args, 'asset', None)
    finding_id = getattr(args, 'finding', None)
    resource_type = getattr(args, 'resource_type', None)
    account_id = getattr(args, 'account', None)
    tag = getattr(args, 'tag', None)
    days = getattr(args, 'days', None)
    jira_ticket = getattr(args, 'jira', None)
    output_format = getattr(args, 'format', 'text')

    if not reason:
        print("Error: Reason is required (--reason)", file=sys.stderr)
        return 1

    try:
        # Parse tag
        tag_key, tag_value = None, None
        if tag:
            if '=' in tag:
                tag_key, tag_value = tag.split('=', 1)
            else:
                tag_key = tag

        # Determine expiry
        expires_at = None
        if days:
            from datetime import timedelta
            expires_at = datetime.now(timezone.utc) + timedelta(days=days)

        # Create exception based on type
        exception_type = ExceptionType(exc_type)
        exception_scope = ExceptionScope(scope)

        exception = PolicyException(
            exception_type=exception_type,
            scope=exception_scope,
            status=ExceptionStatus.APPROVED,
            reason=reason,
            created_by=created_by,
            expires_at=expires_at,
            policy_id=policy_id,
            asset_id=asset_id,
            finding_id=finding_id,
            resource_type=resource_type,
            account_id=account_id,
            tag_key=tag_key,
            tag_value=tag_value,
            jira_ticket=jira_ticket,
        )

        manager.store.save(exception)

        if output_format == 'json':
            print(json.dumps(exception.to_dict(), indent=2))
        else:
            print(f"Created exception: {exception.id}")
            print(f"Type: {exception.exception_type.value}")
            print(f"Scope: {exception.scope.value}")
            if expires_at:
                print(f"Expires: {expires_at.isoformat()}")

        return 0

    except ValueError as e:
        print(f"Invalid value: {e}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"Error creating exception: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_suppress(args: argparse.Namespace) -> int:
    """Create a suppression."""
    manager = get_exception_manager()
    scope = getattr(args, 'scope', 'finding')
    reason = getattr(args, 'reason', '')
    created_by = getattr(args, 'created_by', 'cli')
    policy_id = getattr(args, 'policy', None)
    asset_id = getattr(args, 'asset', None)
    finding_id = getattr(args, 'finding', None)
    resource_type = getattr(args, 'resource_type', None)
    account_id = getattr(args, 'account', None)
    jira_ticket = getattr(args, 'jira', None)
    output_format = getattr(args, 'format', 'text')

    if not reason:
        print("Error: Reason is required (--reason)", file=sys.stderr)
        return 1

    try:
        exception = manager.create_suppression(
            scope=ExceptionScope(scope),
            reason=reason,
            created_by=created_by,
            policy_id=policy_id,
            asset_id=asset_id,
            finding_id=finding_id,
            resource_type=resource_type,
            account_id=account_id,
            jira_ticket=jira_ticket,
        )

        if output_format == 'json':
            print(json.dumps(exception.to_dict(), indent=2))
        else:
            print(f"Created suppression: {exception.id}")

        return 0

    except Exception as e:
        print(f"Error creating suppression: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_false_positive(args: argparse.Namespace) -> int:
    """Mark finding as false positive."""
    manager = get_exception_manager()
    finding_id = getattr(args, 'finding_id', None)
    reason = getattr(args, 'reason', '')
    created_by = getattr(args, 'created_by', 'cli')
    jira_ticket = getattr(args, 'jira', None)
    output_format = getattr(args, 'format', 'text')

    if not finding_id:
        print("Error: Finding ID is required", file=sys.stderr)
        return 1

    if not reason:
        print("Error: Reason is required (--reason)", file=sys.stderr)
        return 1

    try:
        exception = manager.mark_false_positive(
            finding_id=finding_id,
            reason=reason,
            created_by=created_by,
            jira_ticket=jira_ticket,
        )

        if output_format == 'json':
            print(json.dumps(exception.to_dict(), indent=2))
        else:
            print(f"Marked as false positive: {exception.id}")

        return 0

    except Exception as e:
        print(f"Error marking false positive: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_accept_risk(args: argparse.Namespace) -> int:
    """Create a risk acceptance."""
    manager = get_exception_manager()
    scope = getattr(args, 'scope', 'policy')
    reason = getattr(args, 'reason', '')
    created_by = getattr(args, 'created_by', 'cli')
    approved_by = getattr(args, 'approved_by', None)
    policy_id = getattr(args, 'policy', None)
    asset_id = getattr(args, 'asset', None)
    resource_type = getattr(args, 'resource_type', None)
    account_id = getattr(args, 'account', None)
    days = getattr(args, 'days', 365)
    jira_ticket = getattr(args, 'jira', None)
    notes = getattr(args, 'notes', '')
    output_format = getattr(args, 'format', 'text')

    if not reason:
        print("Error: Reason is required (--reason)", file=sys.stderr)
        return 1

    if not approved_by:
        print("Error: Approver is required (--approved-by)", file=sys.stderr)
        return 1

    try:
        exception = manager.accept_risk(
            scope=ExceptionScope(scope),
            reason=reason,
            created_by=created_by,
            approved_by=approved_by,
            policy_id=policy_id,
            asset_id=asset_id,
            resource_type=resource_type,
            account_id=account_id,
            expires_days=days,
            jira_ticket=jira_ticket,
            notes=notes,
        )

        if output_format == 'json':
            print(json.dumps(exception.to_dict(), indent=2))
        else:
            print(f"Created risk acceptance: {exception.id}")
            print(f"Approved by: {approved_by}")
            if days:
                print(f"Review in: {days} days")

        return 0

    except Exception as e:
        print(f"Error accepting risk: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_revoke(args: argparse.Namespace) -> int:
    """Revoke an exception."""
    manager = get_exception_manager()
    exception_id = getattr(args, 'exception_id', None)
    reason = getattr(args, 'reason', '')

    if not exception_id:
        print("Error: Exception ID is required", file=sys.stderr)
        return 1

    try:
        # Find by partial ID
        all_exceptions = manager.list_exceptions(include_expired=True)
        matches = [e for e in all_exceptions if e.id.startswith(exception_id)]

        if not matches:
            print(f"Exception not found: {exception_id}", file=sys.stderr)
            return 1

        if len(matches) > 1:
            print(f"Multiple exceptions match '{exception_id}'")
            return 1

        exc = matches[0]
        success = manager.revoke_exception(exc.id, reason)

        if success:
            print(f"Revoked exception: {exc.id}")
            return 0
        else:
            print(f"Failed to revoke exception: {exc.id}", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error revoking exception: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_delete(args: argparse.Namespace) -> int:
    """Delete an exception."""
    manager = get_exception_manager()
    exception_id = getattr(args, 'exception_id', None)
    force = getattr(args, 'force', False)

    if not exception_id:
        print("Error: Exception ID is required", file=sys.stderr)
        return 1

    try:
        # Find by partial ID
        all_exceptions = manager.list_exceptions(include_expired=True)
        matches = [e for e in all_exceptions if e.id.startswith(exception_id)]

        if not matches:
            print(f"Exception not found: {exception_id}", file=sys.stderr)
            return 1

        if len(matches) > 1:
            print(f"Multiple exceptions match '{exception_id}'")
            return 1

        exc = matches[0]

        if exc.is_active and not force:
            print(f"Exception is active. Use --force to delete: {exc.id}", file=sys.stderr)
            return 1

        success = manager.delete_exception(exc.id)

        if success:
            print(f"Deleted exception: {exc.id}")
            return 0
        else:
            print(f"Failed to delete exception: {exc.id}", file=sys.stderr)
            return 1

    except Exception as e:
        print(f"Error deleting exception: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_expire(args: argparse.Namespace) -> int:
    """Expire outdated exceptions."""
    manager = get_exception_manager()

    try:
        count = manager.expire_outdated()
        print(f"Expired {count} exception(s)")
        return 0

    except Exception as e:
        print(f"Error expiring exceptions: {e}", file=sys.stderr)
        return 1


def _handle_exceptions_types(args: argparse.Namespace) -> int:
    """List exception types."""
    output_format = getattr(args, 'format', 'table')

    types_info = [
        {
            "type": ExceptionType.SUPPRESSION.value,
            "description": "Permanent suppression of findings",
            "use_case": "Known acceptable configuration",
        },
        {
            "type": ExceptionType.TEMPORARY.value,
            "description": "Time-limited exception with automatic expiry",
            "use_case": "Planned remediation in progress",
        },
        {
            "type": ExceptionType.FALSE_POSITIVE.value,
            "description": "Finding determined to be incorrect",
            "use_case": "Policy doesn't apply to this resource",
        },
        {
            "type": ExceptionType.RISK_ACCEPTED.value,
            "description": "Risk formally accepted with approval",
            "use_case": "Business requirement overrides security",
        },
        {
            "type": ExceptionType.COMPENSATING_CONTROL.value,
            "description": "Alternative security control in place",
            "use_case": "Different control addresses the same risk",
        },
    ]

    if output_format == 'json':
        print(json.dumps(types_info, indent=2))
    else:
        print("Exception Types:\n")
        for t in types_info:
            print(f"  {t['type']}")
            print(f"    {t['description']}")
            print(f"    Use case: {t['use_case']}")
            print()

    return 0


def _handle_exceptions_scopes(args: argparse.Namespace) -> int:
    """List exception scopes."""
    output_format = getattr(args, 'format', 'table')

    scopes_info = [
        {
            "scope": ExceptionScope.FINDING.value,
            "description": "Single specific finding",
            "example": "--finding <finding_id>",
        },
        {
            "scope": ExceptionScope.ASSET.value,
            "description": "All findings for a specific asset",
            "example": "--asset <asset_id>",
        },
        {
            "scope": ExceptionScope.POLICY.value,
            "description": "All findings from a policy",
            "example": "--policy <policy_id>",
        },
        {
            "scope": ExceptionScope.ASSET_POLICY.value,
            "description": "Policy findings for a specific asset",
            "example": "--asset <asset_id> --policy <policy_id>",
        },
        {
            "scope": ExceptionScope.RESOURCE_TYPE.value,
            "description": "All assets of a resource type",
            "example": "--resource-type aws_s3_bucket",
        },
        {
            "scope": ExceptionScope.TAG.value,
            "description": "Assets with specific tag",
            "example": "--tag environment=dev",
        },
        {
            "scope": ExceptionScope.ACCOUNT.value,
            "description": "Entire cloud account",
            "example": "--account 123456789012",
        },
        {
            "scope": ExceptionScope.GLOBAL.value,
            "description": "Global exception (all findings)",
            "example": "--scope global",
        },
    ]

    if output_format == 'json':
        print(json.dumps(scopes_info, indent=2))
    else:
        print("Exception Scopes:\n")
        for s in scopes_info:
            print(f"  {s['scope']}")
            print(f"    {s['description']}")
            print(f"    Example: {s['example']}")
            print()

    return 0


def _handle_exceptions_status(args: argparse.Namespace) -> int:
    """Show exceptions module status."""
    manager = get_exception_manager()
    output_format = getattr(args, 'format', 'text')

    try:
        all_exceptions = manager.list_exceptions(include_expired=True)
        active = manager.get_active_exceptions()

        # Count by type
        by_type = {}
        for exc in all_exceptions:
            t = exc.exception_type.value
            by_type[t] = by_type.get(t, 0) + 1

        # Count by scope
        by_scope = {}
        for exc in all_exceptions:
            s = exc.scope.value
            by_scope[s] = by_scope.get(s, 0) + 1

        # Count by status
        by_status = {}
        for exc in all_exceptions:
            s = exc.status.value
            by_status[s] = by_status.get(s, 0) + 1

        # Expiring soon
        expiring_soon = [e for e in active if e.expires_at and e.days_until_expiry is not None and e.days_until_expiry <= 30]

        status = {
            "module": "exceptions",
            "version": "1.0.0",
            "total_exceptions": len(all_exceptions),
            "active_exceptions": len(active),
            "expiring_soon": len(expiring_soon),
            "exceptions_by_type": by_type,
            "exceptions_by_scope": by_scope,
            "exceptions_by_status": by_status,
            "capabilities": {
                "suppression": True,
                "temporary_exceptions": True,
                "false_positive_marking": True,
                "risk_acceptance": True,
                "compensating_controls": True,
                "auto_expiry": True,
            },
        }

        if output_format == 'json':
            print(json.dumps(status, indent=2))
        else:
            print("Exceptions Module Status")
            print("=" * 40)
            print(f"\nTotal Exceptions: {status['total_exceptions']}")
            print(f"Active Exceptions: {status['active_exceptions']}")
            print(f"Expiring in 30 days: {status['expiring_soon']}")

            if by_type:
                print("\nBy Type:")
                for t, count in sorted(by_type.items()):
                    print(f"  {t}: {count}")

            if by_status:
                print("\nBy Status:")
                for s, count in sorted(by_status.items()):
                    print(f"  {s}: {count}")

        return 0

    except Exception as e:
        print(f"Error getting status: {e}", file=sys.stderr)
        return 1


def add_exceptions_parser(subparsers: argparse._SubParsersAction) -> None:
    """Add exceptions management parser to CLI."""
    exc_parser = subparsers.add_parser(
        'exceptions',
        help='Policy exceptions management',
        description='Manage policy exceptions, suppressions, and risk acceptances',
    )

    exc_subparsers = exc_parser.add_subparsers(
        dest='exceptions_action',
        title='Exception Commands',
    )

    # list command
    list_parser = exc_subparsers.add_parser(
        'list',
        help='List all exceptions',
    )
    list_parser.add_argument(
        '--status', '-s',
        choices=[s.value for s in ExceptionStatus],
        help='Filter by status',
    )
    list_parser.add_argument(
        '--type', '-t',
        choices=[t.value for t in ExceptionType],
        help='Filter by exception type',
    )
    list_parser.add_argument(
        '--scope',
        choices=[s.value for s in ExceptionScope],
        help='Filter by scope',
    )
    list_parser.add_argument(
        '--active',
        action='store_true',
        help='Show only active exceptions',
    )
    list_parser.add_argument(
        '--include-expired',
        action='store_true',
        help='Include expired exceptions',
    )
    list_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # show command
    show_parser = exc_subparsers.add_parser(
        'show',
        help='Show exception details',
    )
    show_parser.add_argument(
        'exception_id',
        help='Exception ID (full or partial)',
    )
    show_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Show verbose details',
    )
    show_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )

    # create command
    create_parser = exc_subparsers.add_parser(
        'create',
        help='Create a new exception',
    )
    create_parser.add_argument(
        '--type', '-t',
        choices=[t.value for t in ExceptionType],
        default='suppression',
        help='Exception type (default: suppression)',
    )
    create_parser.add_argument(
        '--scope', '-s',
        choices=[s.value for s in ExceptionScope],
        default='finding',
        help='Exception scope (default: finding)',
    )
    create_parser.add_argument(
        '--reason', '-r',
        required=True,
        help='Reason for exception',
    )
    create_parser.add_argument(
        '--created-by',
        default='cli',
        help='Creator identifier',
    )
    create_parser.add_argument(
        '--policy',
        help='Target policy ID',
    )
    create_parser.add_argument(
        '--asset',
        help='Target asset ID',
    )
    create_parser.add_argument(
        '--finding',
        help='Target finding ID',
    )
    create_parser.add_argument(
        '--resource-type',
        help='Target resource type',
    )
    create_parser.add_argument(
        '--account',
        help='Target account ID',
    )
    create_parser.add_argument(
        '--tag',
        help='Tag to match (key or key=value)',
    )
    create_parser.add_argument(
        '--days',
        type=int,
        help='Days until expiry (for temporary)',
    )
    create_parser.add_argument(
        '--jira',
        help='Associated Jira ticket',
    )
    create_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )

    # suppress command
    suppress_parser = exc_subparsers.add_parser(
        'suppress',
        help='Create a suppression',
    )
    suppress_parser.add_argument(
        '--scope', '-s',
        choices=[s.value for s in ExceptionScope],
        default='finding',
        help='Suppression scope (default: finding)',
    )
    suppress_parser.add_argument(
        '--reason', '-r',
        required=True,
        help='Reason for suppression',
    )
    suppress_parser.add_argument(
        '--created-by',
        default='cli',
        help='Creator identifier',
    )
    suppress_parser.add_argument(
        '--policy',
        help='Target policy ID',
    )
    suppress_parser.add_argument(
        '--asset',
        help='Target asset ID',
    )
    suppress_parser.add_argument(
        '--finding',
        help='Target finding ID',
    )
    suppress_parser.add_argument(
        '--resource-type',
        help='Target resource type',
    )
    suppress_parser.add_argument(
        '--account',
        help='Target account ID',
    )
    suppress_parser.add_argument(
        '--jira',
        help='Associated Jira ticket',
    )
    suppress_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )

    # false-positive command
    fp_parser = exc_subparsers.add_parser(
        'false-positive',
        help='Mark finding as false positive',
    )
    fp_parser.add_argument(
        'finding_id',
        help='Finding ID to mark',
    )
    fp_parser.add_argument(
        '--reason', '-r',
        required=True,
        help='Reason it is a false positive',
    )
    fp_parser.add_argument(
        '--created-by',
        default='cli',
        help='Creator identifier',
    )
    fp_parser.add_argument(
        '--jira',
        help='Associated Jira ticket',
    )
    fp_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )

    # accept-risk command
    risk_parser = exc_subparsers.add_parser(
        'accept-risk',
        help='Create a risk acceptance',
    )
    risk_parser.add_argument(
        '--scope', '-s',
        choices=[s.value for s in ExceptionScope],
        default='policy',
        help='Risk acceptance scope (default: policy)',
    )
    risk_parser.add_argument(
        '--reason', '-r',
        required=True,
        help='Reason for accepting risk',
    )
    risk_parser.add_argument(
        '--approved-by',
        required=True,
        help='Who approved the risk acceptance',
    )
    risk_parser.add_argument(
        '--created-by',
        default='cli',
        help='Creator identifier',
    )
    risk_parser.add_argument(
        '--policy',
        help='Target policy ID',
    )
    risk_parser.add_argument(
        '--asset',
        help='Target asset ID',
    )
    risk_parser.add_argument(
        '--resource-type',
        help='Target resource type',
    )
    risk_parser.add_argument(
        '--account',
        help='Target account ID',
    )
    risk_parser.add_argument(
        '--days',
        type=int,
        default=365,
        help='Days until review (default: 365)',
    )
    risk_parser.add_argument(
        '--jira',
        help='Associated Jira ticket',
    )
    risk_parser.add_argument(
        '--notes',
        default='',
        help='Additional notes',
    )
    risk_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )

    # revoke command
    revoke_parser = exc_subparsers.add_parser(
        'revoke',
        help='Revoke an exception',
    )
    revoke_parser.add_argument(
        'exception_id',
        help='Exception ID to revoke',
    )
    revoke_parser.add_argument(
        '--reason', '-r',
        default='',
        help='Reason for revocation',
    )

    # delete command
    delete_parser = exc_subparsers.add_parser(
        'delete',
        help='Delete an exception',
    )
    delete_parser.add_argument(
        'exception_id',
        help='Exception ID to delete',
    )
    delete_parser.add_argument(
        '--force',
        action='store_true',
        help='Force delete even if active',
    )

    # expire command
    expire_parser = exc_subparsers.add_parser(
        'expire',
        help='Expire outdated exceptions',
    )

    # types command
    types_parser = exc_subparsers.add_parser(
        'types',
        help='List exception types',
    )
    types_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # scopes command
    scopes_parser = exc_subparsers.add_parser(
        'scopes',
        help='List exception scopes',
    )
    scopes_parser.add_argument(
        '--format', '-f',
        choices=['table', 'json'],
        default='table',
        help='Output format (default: table)',
    )

    # status command
    status_parser = exc_subparsers.add_parser(
        'status',
        help='Show exceptions module status',
    )
    status_parser.add_argument(
        '--format', '-f',
        choices=['text', 'json'],
        default='text',
        help='Output format (default: text)',
    )
