# Gateway performance

On 2026-11-19 a client VM sent traffic to the same private origin before and after
enabling WireGuard and the strict client firewall. Each guest had two x86_64
vCPUs, 1,280 MiB RAM and a virtio NIC on a private QEMU/KVM link. The origin ran
in a separate network namespace on the gateway VM. WAN MTU was 1500 and wg-quick
selected 1420 for the tunnel. Kernel forwarding, nftables and WireGuard used
their distribution defaults. This is a local virtual link shared with other
test processes. Provider bandwidth, physical NIC limits and Internet RTT are
unmeasured. The table gives the final run on each distribution.

| Guest OS and path | TCP received, Mbit/s | iperf3 sender CPU | UDP loss at 10 Mbit/s | UDP jitter, ms | Mean ICMP RTT, ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| Debian 13, direct | 1639.8 | 7.8% | 0% | 0.087 | 0.833 |
| Debian 13, tunnel | 1744.1 | 7.2% | 0% | 0.046 | 1.316 |
| Ubuntu 24.04, direct | 806.4 | 4.9% | 0% | 0.997 | 0.622 |
| Ubuntu 24.04, tunnel | 1887.0 | 7.9% | 0% | 0.057 | 1.082 |

iperf3 used two TCP streams for three seconds and one UDP stream for two seconds.
CPU is iperf3's sender process measurement. It excludes total host and gateway
cryptography costs. RTT is the average of five IPv4 pings with a 1300-byte
payload and fragmentation prohibited. Twenty distinct fixture names resolved
over the tunnel. End-to-end p50/p95, including a new `getent` process for each
lookup, measured 4.13/11.33 ms on Debian and 3.13/9.21 ms on Ubuntu. The TLS
upstream was inside the lab.

Across three runs per distribution during development, direct TCP throughput
ranged from 806 to 5426 Mbit/s and tunneled throughput from 1530 to 1887 Mbit/s.
The direct baseline varied too widely to estimate a percentage cost or speedup
from these short runs.

The [VM harness](../tests/vm/README.md) prints the measurements for each run.
The [validation matrix](validation.md) identifies the guest kernels and tools.
Sustained VPS throughput, CPU saturation, maximum path MTU, NAT capacity, and
reconnect latency distributions remain unmeasured. No performance-specific
sysctl, MTU override or MSS clamping was applied.
