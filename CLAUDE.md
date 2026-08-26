# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

DATUM Gateway implements **Decentralized Alternative Templates for Universal Mining** - a system that enables true decentralized Bitcoin mining by generating block templates locally from the miner's own Bitcoin node rather than receiving templates from a pool.

The Gateway:
- Fetches block templates from local Bitcoin node(s) via RPC/GBT
- Distributes work to mining hardware via Stratum v1 protocol
- Submits solved blocks directly to the Bitcoin network
- Optionally coordinates reward splits with DATUM-supporting pools (pool does NOT create the template)

**Critical Design Principle**: This is Bitcoin-only mining software with many Bitcoin-specific optimizations. The codebase assumes little-endian hardware and will break on big-endian systems.

## Build and Development

### Build
```bash
# Install dependencies first (see README.md for distro-specific commands)
cmake . && make
```

The build system uses CMake and generates:
- `datum_gateway` executable
- Embedded web resources (from www/ directory) via `web_resources.h`
- Git version info via `git_version.h`

### Run Tests
```bash
./datum_gateway --test
```

### Generate Example Config
```bash
./datum_gateway --example-conf > my_config.json
```

### Run Gateway
```bash
./datum_gateway -c datum_gateway_config.json
```

## Configuration Architecture

### Multi-Node Failover (v0.4.0+)

**Recent Major Feature**: The Gateway now supports multiple Bitcoin nodes with automatic failover and recovery (commit 97c4bf5).

#### Configuration Format

**New Multi-Node Format** (recommended):
```json
{
  "bitcoind": {
    "nodes": [
      {
        "rpcurl": "http://primary:8332",
        "rpcuser": "user",
        "rpcpassword": "pass",
        "priority": 0,
        "enabled": true
      },
      {
        "rpcurl": "http://backup:8332",
        "rpcuser": "user2",
        "rpcpassword": "pass2",
        "priority": 1,
        "enabled": true
      }
    ],
    "max_consecutive_failures": 3,
    "failover_cooldown_seconds": 30,
    "try_higher_priority_nodes": true
  }
}
```

**Legacy Single-Node Format** (still supported):
```json
{
  "bitcoind": {
    "rpcurl": "http://localhost:8332",
    "rpcuser": "datum",
    "rpcpassword": "password"
  }
}
```

Legacy format is automatically converted to multi-node internally.

#### Failover Behavior

**Key Implementation Details** (src/datum_jsonrpc.c):

1. **Node Selection**: Nodes are sorted by priority (0 = highest). Active node is `datum_config.bitcoind_current_node_index`.

2. **Failure Detection**: After `max_consecutive_failures` (default: 3) consecutive failures, switch to next node. Failures tracked per node in `T_BITCOIND_NODE_CONFIG`:
   - `consecutive_failures` - reset to 0 on success
   - `last_failure_time` - for cooldown calculation
   - `total_failures` / `total_successes` - lifetime stats

3. **Cooldown Period**: Failed nodes wait `failover_cooldown_seconds` (default: 30s) before retry eligibility.

4. **Recovery Thread**: Background thread (`bitcoind_recovery_thread_func`) periodically tests failed higher-priority nodes. When recovered, logs success and updates node state. Uses `pthread_cond_timedwait` for interruptible sleep.

5. **Failover Serialization**: `bitcoind_failover_mutex` prevents concurrent failover operations from duplicate logging.

**Functions to Use When Modifying**:
- `bitcoind_json_rpc_call_with_failover()` - Main entry point for all RPC calls requiring failover
- `bitcoind_mark_node_failed()` / `bitcoind_mark_node_success()` - Update node state
- `bitcoind_get_next_node()` - Determine next failover target
- `bitcoind_should_try_higher_priority()` - Check if recovery to higher priority is possible

### Configuration System (src/datum_conf.c)

The `datum_config_options[]` array defines all configuration parameters with validation, defaults, and descriptions. The system:
- Parses JSON config file into `global_config_t datum_config`
- Supports legacy single-node and new multi-node formats
- Validates required fields and ranges
- Generates example configs with `--example-conf`

## Code Architecture

### Core Modules

**datum_gateway.c** - Main entry point, signal handling, thread coordination

**datum_jsonrpc.c** - Bitcoin node RPC communication
- JSON-RPC call handling with libcurl
- Multi-node failover logic (570+ lines added in v0.4.0)
- RPC cookie authentication support
- Background recovery thread management

**datum_blocktemplates.c** - Block template management
- Template fetching thread (`datum_gateway_template_thread`)
- Fallback notifier thread for blocknotify alternative
- Template validation and processing
- Uses failover system for all GBT calls

**datum_stratum.c** - Stratum v1 server (~78KB)
- Mining hardware communication
- Work distribution with version rolling (ASICBoost)
- Share validation and duplicate detection
- Client connection management

**datum_protocol.c** - DATUM protocol implementation (~62KB)
- Encrypted pool communication (libsodium)
- Generation transaction coordination
- Work submission to pool
- Obfuscated communication (7.999 bits entropy/byte)

**datum_coinbaser.c** - Generation transaction construction
- Coinbase creation with pool payout splits
- Address validation (base58, bech32)
- Witness commitment handling

**datum_sockets.c** - Low-level socket operations
- epoll-based event handling
- Non-blocking I/O
- Connection lifecycle management

**datum_api.c** - Web dashboard/API (libmicrohttpd)
- Admin interface on port 7152 (default)
- Real-time statistics
- Configuration viewing/modification
- CSRF protection via admin password

**datum_conf.c** - Configuration parsing
- JSON schema with validation
- Multi-node parsing and conversion
- Runtime configuration access

**datum_logger.c** - Logging system
- Console and file logging
- Log levels and rotation
- Thread-safe operations

**datum_utils.c** - Utility functions
- Hex encoding/decoding
- SHA256 hashing
- Time utilities
- Byte manipulation

### Third-Party Code

**thirdparty_base58.c** - Base58 encoding/decoding
**thirdparty_segwit_addr.c** - Bech32 address handling

## Dependencies

Required libraries:
- **libcurl** - HTTP/RPC communication
- **libjansson** - JSON parsing (requires long long support)
- **libmicrohttpd** - Web API server (optional with -DENABLE_API=OFF)
- **libsodium** - Cryptography for DATUM protocol
- **argp** - Argument parsing (standalone library needed on Alpine/FreeBSD)
- **epoll-shim** - epoll support on non-Linux (FreeBSD)

## Important Implementation Notes

### Thread Safety

- `bitcoind_nodes_mutex` protects node state updates
- `bitcoind_failover_mutex` serializes failover operations
- `recovery_thread_mutex` + `recovery_thread_cond` for recovery thread control

Always lock mutexes in the same order to prevent deadlocks.

### Bitcoin Node Requirements

1. Must support GBT (getblocktemplate)
2. **Bitcoin Knots strongly recommended** for template control
3. Block space reservation required: `blockmaxsize=3985000`, `blockmaxweight=3985000`
4. Block notifications: `blocknotify=killall -USR1 datum_gateway`
5. RPC access configured (rpcuser/rpcpassword or rpccookiefile)

### Docker Considerations

- Disable notify_fallback when using Docker
- Use `blocknotify=wget -q -O /dev/null http://datum-gateway:7152/NOTIFY`
- Configure node URLs based on network topology (host.docker.internal, container names, etc.)

## Testing

The codebase includes unit tests for specific modules:
- `datum_stratum_tests()` - Stratum protocol tests
- `datum_conf_tests()` - Configuration parsing tests
- `datum_utils_tests()` - Utility function tests

Run with: `./datum_gateway --test`

## Version and Protocol

- Current version: 0.4.0 (see CMakeLists.txt PROJECT_VERSION)
- Protocol version: Defined in source as `DATUM_PROTOCOL_VERSION`
- Protocol is evolving and subject to breaking changes pre-v1.0
- Git version embedded at build time via cmake/script/GenerateBuildInfo.cmake

## Development Guidelines

1. **Little-endian assumption**: All code assumes little-endian hardware
2. **C standard**: Uses C23 if available, falls back to C11
3. **Error handling**: Log errors with DLOG_ERROR/DLOG_FATAL, use panic_from_thread() for fatal thread errors
4. **RPC calls**: Always use `bitcoind_json_rpc_call_with_failover()` for new code to support multi-node
5. **Thread management**: Ensure proper cleanup and signal handling
6. **API changes**: Remember to update web_resources (www/) if modifying admin interface
7. **Configuration changes**: Update `datum_config_options[]` array and regenerate example with verify script

## Known Limitations

- Linux/64-bit x86 only (other platforms at your own risk)
- Stratum v1 only (no v2 support)
- Pool connection loss disconnects all clients by default (for failover to alternate gateway)
- Share acceptance counts may differ from pool due to latency and validation timing
- Beta software subject to rapid changes and protocol breaking changes

## License

MIT License - See LICENSE file
Copyright (c) 2024-2025 Bitcoin Ocean, LLC & Jason Hughes
