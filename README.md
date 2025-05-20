
# 🛡️ nf-wgobfs

**nf‑wgobfs** is a high‑performance user‑space filter written in Rust for *obfuscating WireGuard traffic*.  
It hides WireGuard’s easily recognizable packet structure from DPI—including machine learning engines—by (1) encrypting the WG header and MAC2, (2) inserting random ballast and a nonce, and (3) reshaping keep-alives.  
The filter works over **NFQUEUE**, so it can be dropped into iptables or nftables without kernel modules—perfect for containers and cloud hosts.

---

## ✨ Features

* 🔐 **Header + MAC2 obfuscation** with ChaCha (ChaCha20‑AVX2 if available, ChaCha6 fallback)  
* 📦 **Random ballast + nonce** → breaks length fingerprinting  
* 🔄 **Adaptive keep‑alive dropper** — hides WG heartbeat patterns while respecting NAT TTL  
* ⚡ **Zero‑copy hot‑path**: minimal `copy_within`, no heap per packet → multi‑Gbps  
* 🧠 **IPv4 & IPv6** support, full UDP/IP checksum recalculation  
* ☁ **Container‑friendly** — pure user‑space, single binary, no kernel patches
* 🦀 **No `unsafe` and no dependency on libc** — memory safety and maximum portability

---

## 🔬 Packet layout (after obfuscation)

```
[IP] [UDP] [CS] [WG_HEADER*] [WG_PAYLOAD] [BALLAST] [L*] [MAC2*] [NONCE]
                └─── XOR ──┘                        └─── XOR ──┘
                
L  – ballast length (1 byte)  
*  – encrypted bytes (ChaCha)
```

---

## 🔗 Inspiration & Differences

The project is inspired by [infinet/xt_wgobfs](https://github.com/infinet/xt_wgobfs) (kernel module).  
`nf-wgobfs` takes the idea to user‑space:

|                     | `xt_wgobfs` (kernel) | **nf‑wgobfs** (user‑space) |
|---------------------|----------------------|----------------------------|
| Layer              | kernel xt target     | NFQUEUE userspace binary   |
| Container‑ready    | ✖                   | ✔                          |
| Kernel upgrade pain| yes (rebuild)        | none                       |
| AVX2 / NEON        | limited              | auto‑detect                |
| ARM VPS            | depends              | ChaCha6 fallback           |
| Debug logging      | `dmesg`              | CLI debug mode             |

---

## 📦 Build & Install

### Dependencies
```bash
sudo apt install libnetfilter-queue-dev    # header + .so for build
rustup toolchain install stable            # if not installed
```

### Compile
```bash
git clone https://github.com/sh0rch/nf-wgobfs.git
cd nf-wgobfs
cargo build --release   # or  cargo build --debug  for verbose logs
```

Resulting binary: `target/release/nf-wgobfs`

---

## 🔧 Quick start

### 1. Prepare configuration file

Default path is `/etc/nf_wgobfs.conf` (override with `NF_WGOBFS_CONF=/path`):

```ini
# queue:direction:name:key[:F|S:mtu]
1:out:wg_out:0123456789abcdef0123456789abcdef:F:1350
2:in:wg_in:fedcba9876543210fedcba9876543210   # auto cipher, mtu 1500
```

* **queue** – NFQUEUE number (matches iptables rule).
* **direction** – `in` or `out` (case‑insensitive).
* **name** – Free‑form tag for logs.
* **key** – 32‑byte hex ASCII (same on both ends).
* **F / S** – *(optional)* cipher mode:

  * `F` – "Fast" (try AVX2 ChaCha20, fallback to ChaCha6)
  * `S` – "Standard" (always ChaCha6)
* **mtu** – *(optional)* effective MTU on external interface, *not WireGuard interface!* (default 1500).

### 2. Wire Firewall
#### » nftables rules

```bash
sudo nft add table inet myfilter

sudo nft add chain inet myfilter in_chain {
    type filter hook prerouting priority 0; policy accept;
}

sudo nft add chain inet myfilter out_chain {
    type filter hook postrouting priority 0; policy accept;
}

# Example: send all UDP to NFQUEUE
sudo nft add rule inet myfilter in_chain udp dport <LOCAL WG PORT> sport <REMOTE WG PORT> queue num 0
sudo nft add rule inet myfilter out_chain udp sport <LOCAL WG PORT> dport <REMOTE WG PORT>  queue num 1
```

#### » iptables *(if you want)*

```bash
# Inbound (deobfuscation) — before routing
sudo iptables -t mangle -A PREROUTING -p udp --dport <LOCAL WG PORT> --sport <REMOTE WG PORT>  -j NFQUEUE --queue-num 0

# Outbound (obfuscation) — after routing
sudo iptables -t mangle -A POSTROUTING -p udp --sport <LOCAL WG PORT> --dport <REMOTE WG PORT> -j NFQUEUE --queue-num 1
```

*One queue can manage all your WG tunnels. But you must differentiate INBOUND and OUTBOUND traffic to different queues. For better performance, it is better to choose two queues (IN, OUT) per tunnel.*

### 3. Run filter

```bash
sudo ./nf-wgobfs
```

#### Command‑line reference

```text
nf_wgobfs [COMMAND]

                      start all NFQUEUEs in foreground
--queue <n>           NFQUEUE number (default 0) in foreground
--check-cipher        detect best cipher mode (for manual specification in the config file)
--generate-units      prepare systemd units to /tmp/nf_wgobfs
```

---

Environment variables:

| Variable          | Meaning                                                 |
| ----------------- | ------------------------------------------------------ |
| `NF_WGOBFS_CONF`  | Alternative path to config file                        |
| `NF_WGOBFS_QUEUE` | Override queue number passed to program (rarely needed)|

---

## 🛠️ Service example (systemd)

Generate and install automatically:
```bash
sudo ./nf-wgobfs --generate-units
sudo cp /tmp/nf_wgobfs/nf_wgobfs@*.service /etc/systemd/system/
sudo cp /tmp/nf_wgobfs/nf_wgobfs.target /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable nf_wgobfs.target
sudo systemctl start nf_wgobfs.target
```

---

## 🚦 CPU Compatibility

* **x86‑64 with AVX2** → add `F` to the config file (ChaCha20‑AVX2 ~7 Gbps on R5 3600)  
* **cloud ARM** (Graviton / Ampere) → use `S` in the config  
* **legacy VPS (no SIMD)** → auto‑fallback to ChaCha6

---

## 🏎 Benchmarks

| Host                | Cipher        | Throughput | CPU |
|---------------------|--------------|-----------:|----:|
| Ryzen 5 3600        | ChaCha20‑AVX2| 5.9 Gbps   | 28% |
| Neoverse N1 VM      | ChaCha6      | 2.7 Gbps   | 35% |
| Raspberry Pi 4      | ChaCha6      | 1.1 Gbps   | 62% |

---

## 🍰 Contributing

See **CONTRIBUTING.md** – PRs & issues are welcome!

---

## 📄 License

MIT © sh0rch

