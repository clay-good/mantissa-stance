# stance.web.server

HTTP server for Mantissa Stance dashboard.

Provides a simple HTTP server for serving the dashboard UI
and JSON API endpoints for posture data.

## Contents

### Classes

- [StanceRequestHandler](#stancerequesthandler)
- [StanceServer](#stanceserver)

## StanceRequestHandler

**Inherits from:** SimpleHTTPRequestHandler

HTTP request handler for Stance dashboard.

Handles both static file serving and JSON API endpoints.

### Attributes

| Name | Type | Default |
|------|------|---------|
| `storage` | `StorageBackend | None` | - |
| `_attack_paths_cache` | `dict[(str, Any)]` | `{}` |
| `_attack_paths_cache_time` | `datetime | None` | - |
| `_presets` | `dict[(str, dict)]` | `{}` |
| `_notification_destinations` | `dict[(str, dict[(str, Any)])]` | `{}` |
| `_notification_config` | `dict[(str, Any)]` | `{'enabled': False, 'notify_on_critical': True, 'notify_on_high': False, 'notify_on_scan_complete': False, 'notify_on_new_findings': True, 'min_severity': 'high', 'default_destination': None}` |
| `_notification_history` | `list[dict[(str, Any)]]` | `[]` |

### Methods

#### `__init__(self, *args, **kwargs)`

**Parameters:**

- `*args`
- `**kwargs`

#### `do_GET(self)`

Handle GET requests.

#### `do_POST(self)`

Handle POST requests.

#### `log_message(self, format: str, *args)`

Suppress default logging.

**Parameters:**

- `format` (`str`)
- `*args`

## StanceServer

Simple HTTP server for Stance dashboard.

Serves the dashboard UI and provides JSON API endpoints
for accessing posture data.

### Properties

#### `url(self) -> str`

Get the server URL.

**Returns:**

`str`

### Methods

#### `__init__(self, host: str = 127.0.0.1, port: int = 8080, storage: StorageBackend | None)`

Initialize the server.

**Parameters:**

- `host` (`str`) - default: `127.0.0.1` - Host to bind to (default: 127.0.0.1)
- `port` (`int`) - default: `8080` - Port to listen on (default: 8080)
- `storage` (`StorageBackend | None`) - Storage backend to use (default: LocalStorage)

#### `start(self)`

Start the HTTP server (blocking).  This method blocks until the server is stopped.

#### `start_background(self) -> threading.Thread`

Start server in background thread.

**Returns:**

`threading.Thread` - Thread running the server

#### `stop(self)`

Stop the server.
