# xv6 Networking Implementation

A comprehensive networking stack implementation for xv6. This project adds full networking capabilities including a network driver, protocol stack, and user-space networking utilities.

## What Was Implemented

### Core Components
- E1000 NIC Driver (`kernel/e1000.c`) - DMA-based packet transmission and reception with circular ring buffers
- Network Stack (`kernel/net.c`) - Ethernet, ARP, IP, UDP, and ICMP protocol implementations
- UDP Socket API - System calls for `bind()`, `send()`, and `recv()` with per-port packet queuing
- Raw Socket API - Protocol-level packet access via `rawsock_bind()`, `rawsock_send()`, `rawsock_recv()`

### User Programs
- **`host`** (`user/host.c`) - DNS client for hostname resolution
- **`ping`** (`user/ping.c`) - ICMP echo utility with integrated DNS support

## Noted Limitations / Future Updates

- QEMU emulation appears to be a bottleneck, at both the network stack layers (particularly in the packet arrival rate and the emulated NIC to be able to take in bursty traffic) and in the connection between user programs with the outside world (with consistent website-neutral overhead on ping)
- Significantly increased drops with bursty traffic - one working solution has just been to increase the queue size (for each port), but this seems like an untenable solution. Also note apparent kernel saturation significantly increases the time to add new packets to the queue as traffic increases.
- Idea: security layer (TLS, TCP support) to build on top of basic UDP networking with modern protocols
- Idea: HTTP client, make requests, download webpages

## References and Links

- MIT Lab: https://pdos.csail.mit.edu/6.1810/2025/labs/net.html
- Lab Base Code: https://pdos.csail.mit.edu/6.1810/2025/labs/util.html (repo in first block)
- RFC 1035 - Domain Names - Implementation and Specification (DNS): https://www.rfc-editor.org/rfc/rfc1035
- RFC 792 - Internet Control Message Protocol (ICMP): https://www.rfc-editor.org/rfc/rfc792
