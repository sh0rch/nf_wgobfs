# nf-wgobfs v1.0.0 — First public Release

**nf-wgobfs** is a high-performance user-space filter for obfuscating WireGuard traffic, written in Rust.  
It is designed to defeat DPI and traffic fingerprinting by encrypting WireGuard headers and MAC2, inserting random ballast and a nonce, and reshaping keep-alive packets.  
nf-wgobfs operates over NFQUEUE, making it easy to integrate with iptables or nftables without kernel modules—ideal for containers and cloud deployments.

---

## 🚀 Features

- **ChaCha20-based header & MAC2 obfuscation**  
  Uses the fastest available ChaCha20 implementation (OpenSSL ASM or pure Rust fallback).
- **Random ballast & nonce insertion**  
  Breaks length fingerprinting and adds entropy to each packet.
- **Adaptive keep-alive dropper**  
  Hides WireGuard heartbeat patterns while respecting NAT timeouts.
- **Zero-copy hot-path**  
  Minimal memory copying, no heap allocations per packet—multi-Gbps performance.
- **IPv4 & IPv6 support**  
  Full UDP/IP checksum recalculation.
- **Container-friendly**  
  Pure user-space, single binary, no kernel patches required.
- **No `unsafe` and no libc dependency**  
  Maximum portability and memory safety.
- **Systemd integration**  
  Generates ready-to-use unit files for easy service management.

> Here is a sample result of the comparison test for encrypting a 1 MiB block(Intel i7-11800H):
>
> chacha20 (RustCrypto)   : 113.3736ms
>fast_chacha ("ASM")     : <strong><span style="color: red;">561.6µs</span></strong>
>fast_chacha (Fallback)  : 24.8241ms
>
> _Actual results of tests you can see on [FastChacha 20 Github Actions page](https://github.com/sh0rch/fast_chacha/actions/workflows/tests.yml)._
---

## 🛠️ How it works

- **Obfuscates** the first 16 bytes of the WireGuard header and MAC2 using ChaCha20.
- **Inserts** a random-length ballast and a nonce to break static packet signatures.
- **Handles** both inbound and outbound traffic via separate NFQUEUEs.
- **Automatically detects** and uses the fastest available ChaCha20 backend for your CPU (x86, x86_64, ARM, MIPS, etc).

---

## 📦 Packaging & Platforms

- Prebuilt packages: `.tar.gz`, `.deb`, `.rpm`, `.apk` for all major Linux architectures (x86_64, i686, aarch64, mips, mipsel, mips64, mips64el).
- Fully automated CI builds and tests for all supported targets.
- No kernel modules or patches required.

---

## 🛠️ Installing Unsigned Packages

If you install `.deb`, `.rpm`, or `.apk` packages built by CI, they may be unsigned.  
To install such packages, use the following commands:

**Debian/Ubuntu (.deb):**
```sh
sudo dpkg -i nf_wgobfs-<version>-<arch>.deb
sudo apt-get install -f  # To fix any missing dependencies
```

**RedHat/CentOS/Fedora (.rpm):**
```sh
sudo rpm -i --nosignature nf_wgobfs-<version>-<arch>.rpm
```

**Alpine (.apk):**
```sh
sudo apk add --allow-untrusted nf_wgobfs-<version>-<arch>.apk
```

> _Note: Installing unsigned packages is safe if you trust the source (e.g., official CI artifacts)._

---


## 🗃️ Using Standalone Binaries

You can always use the standalone binaries from the `.tar.gz` archives for your architecture.  
Just extract the archive and run the `nf_wgobfs` binary directly — no package manager or specific Linux distribution required.

```sh
sudo tar --numeric-owner --preserve-permissions -xzf /path/to/nf_wgobfs-x86_64-s-<version>-<arch>.tar.gz -C /
```

---

## 🔧 Quick Start


See [README](./README.md) for detailed instructions and configuration examples.


---

## 📄 License

MIT © 2025 sh0rch

---

_Thank you for trying nf-wgobfs!  
Feedback, issues, and PRs are welcome._
