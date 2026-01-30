# MikroTik Double NAT-PMP

A NAT-PMP (RFC 6886) server for double-NAT scenarios that synchronizes port mappings between a MikroTik router and VPN gateway.

## Overview

This NAT-PMP server creates coordinated port mappings across two NAT layers, allowing clients behind a VPN-connected MikroTik router to receive incoming connections.

```
                                    Internet
                                        │
                                   VPN Gateway (NAT-PMP)
                                        │
┌───────────────────────────────────────┼───────────────────────────────────────┐
│ MikroTik Router                       │                                       │
│                              ┌────────┴────────┐                              │
│                              │  WireGuard/VPN  │                              │
│                              │   Interface     │                              │
│                              └────────┬────────┘                              │
│                                       │                                       │
│                              ┌────────┴────────┐                              │
│                              │  double-natpmp  │◄─── This service             │
│                              │     :5351       │                              │
│                              └────────┬────────┘                              │
│                                       │                                       │
└───────────────────────────────────────┼───────────────────────────────────────┘
                                        │
                                   LAN Clients
                              (NAT-PMP requests)
```

## Quick Start

```bash
# Build
go build -o double-natpmp

# Run
VPN_GATEWAY=10.2.0.1 \
MIKROTIK_API_ADDRESS=192.168.1.254:8728 \
MIKROTIK_API_PASSWORD=your-password \
./double-natpmp
```

## Configuration

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `VPN_GATEWAY` | VPN gateway IP address | `10.2.0.1` |
| `MIKROTIK_API_ADDRESS` | MikroTik API endpoint | `192.168.1.254:8728` |
| `MIKROTIK_API_PASSWORD` | MikroTik API password | - |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | NAT-PMP listen address | `:5351` |
| `MIKROTIK_API_USER` | MikroTik API username | `admin` |
| `MIKROTIK_API_TLS` | Use TLS for API connection | `false` |
| `MIKROTIK_IN_INTERFACE` | Interface for dst-nat rules | auto-detected |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` |

## Features

- **RFC 6886 compliant** - Full NAT-PMP protocol implementation
- **Double-NAT orchestration** - Synchronized mappings across both NAT layers
- **Automatic interface detection** - Determines MikroTik interface from VPN gateway routing
- **Connection pooling** - 4 concurrent MikroTik API connections for parallel operations
- **Per-mapping serialization** - Concurrent requests for different ports run in parallel; same-port requests are serialized
- **Transaction rollback** - Automatic cleanup if mapping creation fails partway
- **Periodic reconciliation** - Removes orphaned MikroTik rules every 10 minutes
- **Graceful shutdown** - Cleanup of all mappings on termination
- **Rate limiting** - Maximum 100 concurrent request handlers
- **Auto-reconnection** - Recovers from MikroTik API connection failures

## How It Works

### Port Mapping Flow

1. Client sends NAT-PMP mapping request to this server
2. Server creates **persistent** dst-nat rule on MikroTik router
3. Server forwards request to VPN gateway NAT-PMP server
4. VPN gateway returns granted lifetime (often shorter, e.g., 60s)
5. Server returns VPN's actual lifetime to client
6. Client renews before expiration; server only refreshes VPN mapping (MikroTik rule persists)

### Why Two Mappings?

| Layer | Mapping | Lifetime | Purpose |
|-------|---------|----------|---------|
| MikroTik | dst-nat rule | Persistent | Forward traffic from VPN interface to LAN client |
| VPN Gateway | NAT-PMP mapping | Time-limited | Forward traffic from internet to VPN tunnel |

The MikroTik rule persists because it's cheap and the server tracks it. The VPN mapping has a short lifetime (set by the VPN provider), requiring client-driven renewals.

## MikroTik Setup

The service creates dst-nat rules with comments prefixed `double-natpmp-`. Ensure your MikroTik API user has permissions to:

- Read/write `/ip/firewall/nat`
- Read `/ip/route` (for interface auto-detection)

Example MikroTik user setup:
```
/user group add name=natpmp policy=read,write,test,api,!ftp,!reboot,!policy,!sensitive
/user add name=natpmp group=natpmp password=your-password
```

The `test` policy is required for `/ip/route/check` (interface auto-detection).

## Building

```bash
go build -o double-natpmp
```

## License

MIT
