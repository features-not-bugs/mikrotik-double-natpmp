# MikroTik Double NAT-PMP

A NAT-PMP (RFC 6886) server for double-NAT scenarios that synchronizes port mappings between a MikroTik router and an upstream VPN gateway.

## Overview

This service creates coordinated port mappings across two NAT layers, allowing clients behind a VPN-connected MikroTik router to receive incoming connections.

**Requires:** An upstream VPN gateway that supports NAT-PMP port forwarding (e.g., [ProtonVPN](https://pr.tn/ref/NDPEKXJJ)).

<p align="center">
  <img src=".github/diagrams/port-forward-diagram.svg" width="100%">
</p>

### Port Mapping Flow

1. LAN client sends NAT-PMP mapping request to the MikroTik router (default gateway)
2. MikroTik firewall dst-nats the request to the double-natpmp container
3. double-natpmp creates a **persistent** dst-nat rule on the MikroTik router, forwarding the requested port to the LAN client (uses suggested port if available, otherwise assigns a random port)
4. double-natpmp forwards the NAT-PMP request upstream to the VPN gateway, using the MikroTik dst-nat port as the internal port
5. VPN gateway returns a response with the granted external port and lifetime
6. double-natpmp returns the response to the LAN client with the VPN gateway's external port and lifetime

### Why Two Mappings?

Both mappings are required to complete the traffic flow from the internet to your LAN client. Without the MikroTik dst-nat rule, traffic arriving from the VPN gateway would be dropped at the router. Without the VPN gateway mapping, traffic would never reach the VPN tunnel in the first place.

1. **VPN Gateway** — Incoming internet traffic hits the VPN provider's public IP. The NAT-PMP mapping forwards it through the VPN tunnel to your MikroTik router.

2. **MikroTik Router** — Traffic arrives on the WireGuard interface. The dst-nat rule forwards it to the actual LAN client.

| Layer | Mapping | Lifetime | Purpose |
|-------|---------|----------|---------|
| VPN Gateway | NAT-PMP mapping | Time-limited (e.g., 60s) | Internet → VPN tunnel |
| MikroTik | dst-nat rule | Persistent | VPN interface → LAN client |

The VPN mapping has a short lifetime enforced by the provider, so clients must send periodic renewals to keep the port open. The MikroTik dst-nat rule is kept persistent between renewals to avoid unnecessary churn, but is automatically deleted when the NAT-PMP lifetime expires without renewal.

## Features

- **RFC 6886 compliant** - Full NAT-PMP protocol implementation
- **Double-NAT orchestration** - Synchronized mappings across both NAT layers
- **Automatic interface detection** - Determines MikroTik interface from VPN gateway routing
- **Connection pooling** - 4 concurrent MikroTik API connections
- **Per-mapping serialization** - Different ports run in parallel; same-port requests serialize
- **Transaction rollback** - Automatic cleanup on partial failures
- **Periodic reconciliation** - Removes orphaned MikroTik rules every 10 minutes
- **Graceful shutdown** - Cleanup of all mappings on termination
- **Auto-reconnection** - Recovers from MikroTik API connection failures

## Quick Start

```bash
docker pull ghcr.io/features-not-bugs/mikrotik-double-natpmp:latest

docker run -d \
  -e VPN_GATEWAY=10.2.0.1 \
  -e MIKROTIK_API_ADDRESS=192.168.88.1:8728 \
  -e MIKROTIK_API_PASSWORD=your-password \
  -p 5351:5351/udp \
  ghcr.io/features-not-bugs/mikrotik-double-natpmp:latest
```

## MikroTik Container Deployment

The recommended deployment runs this service as a container directly on MikroTik RouterOS (v7.4+).

### 1. Enable Container Mode

```
/system/device-mode/update container=yes
```

Reboot after running this command.

### 2. Create API User

The service needs API access to manage dst-nat rules:

```
/user/group add name=natpmp policy=read,write,test,api,!ftp,!reboot,!policy,!sensitive
/user add name=natpmp group=natpmp password=your-password
```

The `test` policy is required for interface auto-detection via `/ip/route/check`.

### 3. Deploy Container

```
# Configure registry
/container/config set registry-url=https://ghcr.io tmpdir=disk1/tmp

# Create network interface
/interface/veth add name=veth-natpmp address=192.168.88.250/24 gateway=192.168.88.1
/interface/bridge/port add bridge=bridge interface=veth-natpmp

# Set environment variables
/container/envs add name=natpmp key=VPN_GATEWAY value="10.2.0.1"
/container/envs add name=natpmp key=MIKROTIK_API_ADDRESS value="192.168.88.1:8728"
/container/envs add name=natpmp key=MIKROTIK_API_PASSWORD value="your-password"

# Create and start container
/container add remote-image=ghcr.io/features-not-bugs/mikrotik-double-natpmp:latest \
    interface=veth-natpmp envlist=natpmp logging=yes
/container/start 0
```

### 4. Redirect NAT-PMP Requests

NAT-PMP clients send requests to their default gateway on UDP port 5351. Add a dst-nat rule to redirect these to the container:

```
/ip/firewall/nat add chain=dstnat protocol=udp dst-port=5351 \
    action=dst-nat to-addresses=192.168.88.250 \
    comment="Redirect NAT-PMP to double-natpmp container"
```

## Configuration

### Required

| Variable | Description | Example |
|----------|-------------|---------|
| `VPN_GATEWAY` | Upstream VPN gateway IP | `10.2.0.1` |
| `MIKROTIK_API_ADDRESS` | MikroTik API endpoint | `192.168.88.1:8728` |
| `MIKROTIK_API_PASSWORD` | MikroTik API password | - |

### Optional

| Variable | Description | Default |
|----------|-------------|---------|
| `LISTEN_ADDR` | NAT-PMP listen address | `:5351` |
| `MIKROTIK_API_USER` | MikroTik API username | `admin` |
| `MIKROTIK_API_TLS` | Use TLS for API | `false` |
| `MIKROTIK_IN_INTERFACE` | Interface for dst-nat rules | auto-detected |
| `LOG_LEVEL` | `DEBUG`, `INFO`, `WARN`, `ERROR` | `INFO` |

## License

MIT
