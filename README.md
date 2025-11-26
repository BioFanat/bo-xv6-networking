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

## References and Links

- MIT Lab: https://pdos.csail.mit.edu/6.1810/2025/labs/net.html
- Lab Base Code: https://pdos.csail.mit.edu/6.1810/2025/labs/util.html (repo in first block)
- RFC 1035 - Domain Names - Implementation and Specification (DNS): https://www.rfc-editor.org/rfc/rfc1035
- RFC 792 - Internet Control Message Protocol (ICMP): https://www.rfc-editor.org/rfc/rfc792
