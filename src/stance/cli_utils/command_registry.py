"""
Command registry for CLI routing.

This module provides a centralized command registry that eliminates
the repetitive if/elif chains found in 30+ CLI modules.
"""

from __future__ import annotations

import argparse
import logging
from dataclasses import dataclass, field
from typing import Any, Callable

logger = logging.getLogger(__name__)


# Type alias for command handlers
CommandHandler = Callable[[argparse.Namespace], int]


@dataclass
class CommandInfo:
    """Information about a registered command."""

    name: str
    handler: CommandHandler
    description: str = ""
    aliases: list[str] = field(default_factory=list)
    subcommands: dict[str, "CommandInfo"] = field(default_factory=dict)


class CommandRegistry:
    """
    Registry for CLI command handlers.

    Provides a clean way to register and route commands, replacing
    the repetitive if/elif chains in CLI modules.

    Usage:
        from stance.cli_utils.command_registry import CommandRegistry

        # Create registry and register commands
        registry = CommandRegistry()
        registry.register('list', cmd_list, description='List resources')
        registry.register('show', cmd_show, description='Show resource details')
        registry.register('create', cmd_create, description='Create resource')

        # Route to appropriate handler
        return registry.route(args, action_attr='action')

        # Or with builder pattern
        return (CommandRegistry()
            .register('list', cmd_list)
            .register('show', cmd_show)
            .route(args))
    """

    def __init__(self, default_handler: CommandHandler | None = None) -> None:
        """
        Initialize the command registry.

        Args:
            default_handler: Optional handler to use when no action matches
        """
        self._commands: dict[str, CommandInfo] = {}
        self._aliases: dict[str, str] = {}
        self._default_handler = default_handler

    def register(
        self,
        name: str,
        handler: CommandHandler,
        description: str = "",
        aliases: list[str] | None = None,
    ) -> "CommandRegistry":
        """
        Register a command handler.

        Args:
            name: The command name (action value)
            handler: The handler function to call
            description: Optional description for help text
            aliases: Optional list of alias names

        Returns:
            self for method chaining
        """
        command_info = CommandInfo(
            name=name,
            handler=handler,
            description=description,
            aliases=aliases or [],
        )
        self._commands[name] = command_info

        # Register aliases
        for alias in aliases or []:
            self._aliases[alias] = name

        return self

    def register_subcommand(
        self,
        parent_name: str,
        name: str,
        handler: CommandHandler,
        description: str = "",
    ) -> "CommandRegistry":
        """
        Register a subcommand under a parent command.

        Args:
            parent_name: The parent command name
            name: The subcommand name
            handler: The handler function to call
            description: Optional description

        Returns:
            self for method chaining
        """
        if parent_name not in self._commands:
            raise ValueError(f"Parent command '{parent_name}' not registered")

        self._commands[parent_name].subcommands[name] = CommandInfo(
            name=name,
            handler=handler,
            description=description,
        )
        return self

    def unregister(self, name: str) -> "CommandRegistry":
        """
        Unregister a command.

        Args:
            name: The command name to unregister

        Returns:
            self for method chaining
        """
        if name in self._commands:
            # Remove aliases
            for alias in self._commands[name].aliases:
                self._aliases.pop(alias, None)
            del self._commands[name]
        return self

    def route(
        self,
        args: argparse.Namespace,
        action_attr: str = "action",
        subaction_attr: str | None = None,
    ) -> int:
        """
        Route to the appropriate command handler.

        Args:
            args: Parsed command-line arguments
            action_attr: Name of the attribute containing the action
            subaction_attr: Optional name of attribute for subcommand action

        Returns:
            Exit code from the handler (0 for success)
        """
        action = getattr(args, action_attr, None)

        # Handle missing action
        if action is None:
            if self._default_handler:
                return self._default_handler(args)
            logger.warning(f"No action specified in args.{action_attr}")
            return 1

        # Resolve aliases
        if action in self._aliases:
            action = self._aliases[action]

        # Find and execute handler
        if action in self._commands:
            command_info = self._commands[action]

            # Check for subcommand
            if subaction_attr and command_info.subcommands:
                subaction = getattr(args, subaction_attr, None)
                if subaction and subaction in command_info.subcommands:
                    return command_info.subcommands[subaction].handler(args)

            return command_info.handler(args)

        # No matching command
        logger.warning(f"Unknown action: {action}")
        if self._default_handler:
            return self._default_handler(args)
        return 1

    def get_handler(self, name: str) -> CommandHandler | None:
        """
        Get the handler for a command name.

        Args:
            name: The command name

        Returns:
            The handler function or None if not found
        """
        # Resolve aliases
        if name in self._aliases:
            name = self._aliases[name]
        if name in self._commands:
            return self._commands[name].handler
        return None

    def list_commands(self) -> list[str]:
        """
        List all registered command names.

        Returns:
            List of command names
        """
        return list(self._commands.keys())

    def get_command_info(self, name: str) -> CommandInfo | None:
        """
        Get information about a registered command.

        Args:
            name: The command name

        Returns:
            CommandInfo or None if not found
        """
        # Resolve aliases
        if name in self._aliases:
            name = self._aliases[name]
        return self._commands.get(name)

    def set_default(self, handler: CommandHandler) -> "CommandRegistry":
        """
        Set the default handler for unknown/missing actions.

        Args:
            handler: The default handler function

        Returns:
            self for method chaining
        """
        self._default_handler = handler
        return self

    def __contains__(self, name: str) -> bool:
        """Check if a command is registered."""
        return name in self._commands or name in self._aliases


class NestedCommandRegistry:
    """
    Registry that supports nested command hierarchies.

    Useful for commands with multiple levels of subcommands like:
    stance auth users list
    stance auth users create

    Usage:
        registry = NestedCommandRegistry()
        registry.register(['auth', 'users', 'list'], cmd_auth_users_list)
        registry.register(['auth', 'users', 'create'], cmd_auth_users_create)
        registry.register(['auth', 'status'], cmd_auth_status)

        # Route with multiple action attributes
        return registry.route(args, ['auth_action', 'users_action'])
    """

    def __init__(self) -> None:
        """Initialize the nested registry."""
        self._root: dict[str, Any] = {}
        self._default_handlers: dict[tuple[str, ...], CommandHandler] = {}

    def register(
        self,
        path: list[str],
        handler: CommandHandler,
        description: str = "",
    ) -> "NestedCommandRegistry":
        """
        Register a command at a path.

        Args:
            path: List of command path components (e.g., ['auth', 'users', 'list'])
            handler: The handler function
            description: Optional description

        Returns:
            self for method chaining
        """
        current = self._root
        for component in path[:-1]:
            if component not in current:
                current[component] = {}
            current = current[component]

        current[path[-1]] = CommandInfo(
            name=path[-1],
            handler=handler,
            description=description,
        )
        return self

    def set_default(
        self,
        path: list[str],
        handler: CommandHandler,
    ) -> "NestedCommandRegistry":
        """
        Set a default handler for a path level.

        Args:
            path: The path prefix to set default for
            handler: The default handler

        Returns:
            self for method chaining
        """
        self._default_handlers[tuple(path)] = handler
        return self

    def route(
        self,
        args: argparse.Namespace,
        action_attrs: list[str],
    ) -> int:
        """
        Route through nested command hierarchy.

        Args:
            args: Parsed command-line arguments
            action_attrs: List of attribute names for each level

        Returns:
            Exit code from the handler
        """
        current = self._root
        path: list[str] = []

        for attr in action_attrs:
            action = getattr(args, attr, None)
            if action is None:
                # Check for default handler at this level
                default = self._default_handlers.get(tuple(path))
                if default:
                    return default(args)
                return 1

            path.append(action)

            if action not in current:
                # Check for default at this level
                default = self._default_handlers.get(tuple(path[:-1]))
                if default:
                    return default(args)
                logger.warning(f"Unknown command: {' '.join(path)}")
                return 1

            item = current[action]
            if isinstance(item, CommandInfo):
                return item.handler(args)
            current = item

        # Reached end without finding handler
        default = self._default_handlers.get(tuple(path))
        if default:
            return default(args)
        return 1


def create_registry_from_module(
    module: Any,
    prefix: str = "cmd_",
    action_attr: str = "action",
) -> CommandRegistry:
    """
    Create a command registry from a module's functions.

    Automatically discovers functions with the given prefix and
    registers them as commands.

    Args:
        module: The module to scan for command functions
        prefix: Function name prefix to look for (default: "cmd_")
        action_attr: The action attribute name for routing

    Returns:
        Configured CommandRegistry

    Example:
        # In cli_users.py:
        def cmd_list(args): ...
        def cmd_create(args): ...
        def cmd_delete(args): ...

        # Auto-register all:
        registry = create_registry_from_module(cli_users)
        # Registers: 'list', 'create', 'delete'
    """
    registry = CommandRegistry()

    for name in dir(module):
        if name.startswith(prefix):
            func = getattr(module, name)
            if callable(func):
                command_name = name[len(prefix) :]
                registry.register(command_name, func)

    return registry
