# MikroTik Double NAT-PMP

A NAT-PMP (RFC 6886) server for double-NAT scenarios that synchronizes port mappings between a MikroTik router and VPN gateway.

## Overview

This NAT-PMP server creates coordinated port mappings across two NAT layers, allowing clients behind a VPN-connected MikroTik router to receive incoming connections. The server handles:

- **PUBLIC_ADDRESS** - Queries VPN gateway for external IP address
- **MAP_UDP/MAP_TCP** - Creates persistent mappings on MikroTik router and time-limited mappings on VPN gateway
- **Mapping renewals** - Allows clients to issue port mapping renewals

## Configuration

Required environment variables:

- `VPN_GATEWAY` - VPN gateway IP address (e.g., `10.2.0.1`)
- `MIKROTIK_API_ADDRESS` - MikroTik API endpoint (e.g., `192.168.1.254:8728`)
- `MIKROTIK_API_PASSWORD` - MikroTik API password

Optional environment variables:

- `LISTEN_ADDR` - NAT-PMP listen address (default: `:5351`)
- `MIKROTIK_API_USER` - MikroTik API username (default: `admin`)
- `MIKROTIK_API_TLS` - Use TLS for API connection (default: `false`)
- `MIKROTIK_IN_INTERFACE` - Interface for dst-nat rules (default: auto-detected from VPN route)
- `LOG_LEVEL` - Logging level: `DEBUG`, `INFO`, `WARN`, `ERROR` (default: `INFO`)

## Features

- **RFC 6886 compliant** - Full NAT-PMP protocol implementation including idempotent deletions
- **Double-NAT orchestration** - Synchronized mappings across both NAT layers
- **Automatic interface detection** - Determines correct MikroTik interface from VPN gateway routing
- **Client-driven lifecycle** - Server returns VPN's actual lifetime (e.g., 60s), client manages renewals
- **Port conflict prevention** - Validates port availability before creating mappings
- **Transaction rollback** - Automatic cleanup on failures
- **Queue-per-port serialization** - Prevents concurrent processing of requests for the same port
- **Periodic reconciliation** - Removes expired mappings and stale MikroTik rules every minute
- **Graceful shutdown** - Cleanup of all mappings on termination
- **PCP fallback support** - Returns `UNSUPP_VERSION` for Port Control Protocol clients to trigger NAT-PMP fallback
- **Concurrency-safe** - Proper locking patterns prevent race conditions

## Architecture

```
Client → NAT-PMP Server → Mapping Service
                              ├─→ MikroTik API → Local Router (persistent rules)
                              └─→ NAT-PMP Client → VPN Gateway (time-limited mappings)
```

### Mapping Lifecycle

1. Client requests mapping with desired lifetime
2. Server creates persistent dst-nat rule on MikroTik router
3. Server forwards request to VPN gateway (may receive shorter lifetime, e.g., 60s)
4. Server returns VPN's actual granted lifetime to client
5. Client sees actual lifetime and initiates renewal before expiration
6. On renewal, server only refreshes VPN mapping (MikroTik rule persists)
7. On expiration without renewal, periodic reconciliation removes stale mappings

This design allows the MikroTik router rules to persist while VPN gateway mappings are renewed as needed based on the gateway's lifetime policy.
