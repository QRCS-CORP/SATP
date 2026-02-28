# SATP - Symmetric Authenticated Tunneling Protocol

[![Build](https://github.com/QRCS-CORP/SATP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/SATP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SATP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SATP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/satp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/satp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SIAP/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/SATP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![Docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SATP/)
[![Release](https://img.shields.io/github/v/release/QRCS-CORP/SATP)](https://github.com/QRCS-CORP/SATP/releases/tag/2025-11-04)
[![Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/SATP.svg)](https://github.com/QRCS-CORP/SATP/commits/main)
[![Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Secure%20Infrastructure&color=brightgreen)](#)

**A post-quantum, certificate-free tunneling protocol that establishes a fully authenticated symmetric session in two packets and under one millisecond.**

---

## Documentation

| Document | Description |
|---|---|
| [Help Documentation](https://qrcs-corp.github.io/SATP/) | Full API and integration reference |
| [Summary Document](https://qrcs-corp.github.io/SATP/pdf/satp_summary.pdf) | Protocol overview and design rationale |
| [Protocol Specification](https://qrcs-corp.github.io/SATP/pdf/satp_specification.pdf) | Formal wire-format and state-machine specification |
| [Formal Analysis](https://qrcs-corp.github.io/SATP/pdf/satp_formal.pdf) | Cryptographic security proofs |
| [Implementation Analysis](https://qrcs-corp.github.io/SATP/pdf/satp_analysis.pdf) | Side-channel and implementation review |
| [Integration Guide](https://qrcs-corp.github.io/SATP/pdf/satp_integration.pdf) | Embedding SATP in your application |

---

## Overview

**SATP (Symmetric Authenticated Tunneling Protocol)** is a post-quantum alternative to TLS and SSH designed for closed, high-assurance environments where certificate infrastructure, asymmetric key-exchange overhead, or quantum risk are unacceptable.

Rather than relying on public-key cryptography, SATP uses a hierarchical pre-distributed key tree. A master key generates server keys; server keys generate per-device key trees. Each session consumes one leaf of that tree and is immediately destroyed, providing forward secrecy by construction. No certificates, no CAs, no online trust anchors.

The handshake is two packets:

1. **Client → Server:** 16-byte device ID + nonce.
2. **Server → Client:** Authenticated session hash.

The tunnel is established and ready for encrypted traffic in under one millisecond.

### Key Properties

- **Post-quantum security** — Built exclusively from SHA-3-family primitives (SHAKE-256, cSHAKE-256, KMAC-256) and the RCS-256 wide-block Rijndael AEAD. Resistant to Grover and Shor attacks.
- **Two-packet handshake** — Minimal round-trip latency; no certificate chain validation or multi-step negotiation.
- **Certificate-free identity** — A 16-byte device ID encodes domain · branch · device · key-index. No X.509, CRLs, or OCSP required.
- **Forward secrecy by consumption** — Each session uses a single, one-time-use key leaf. Compromise of a current key does not expose any past session.
- **Tiny footprint** — Under 30 kB flash and 4 kB RAM. Deployable on Cortex-M0+, PLCs, CubeSats, and industrial embedded controllers.
- **MISRA-aligned implementation** — Written in C23 with safety and auditability in mind.

---

## Cryptographic Core

| Primitive | Role | Quantum Security Margin |
|---|---|---|
| **RCS-256** | Stream cipher + AEAD | ≥ 2¹²⁸ (Grover-bounded) |
| **SHAKE-256 / cSHAKE-256** | Key derivation and hashing | ≥ 2¹²⁸ pre-image resistance |
| **KMAC-256** | Packet authentication | Tag-forgery probability ≤ 2⁻¹²⁸ |
| **SCB-KDF** | Password hardening and authentication | ≥ 2²⁰ CPU·MiB per guess |

---

## Quick Start: Running the Example

The repository includes a self-contained **Server** and **Client** example that can be run on a single machine for immediate evaluation. No infrastructure, certificates, or configuration files are needed — key generation is automatic on first launch.

### Step 1 — Start the Server

Build and launch the **Server** project. On first run, SATP detects that no server key exists and generates a complete key hierarchy automatically:

```
server> The server-key was not detected, generating new master/server keys.
server> The user passphrase has been generated: UOD)>//jx|(e"p\.fzlY~D\RO:Huz2[i
server> The device-key has been saved to C:\Users\<username>\Documents\SATP\devkey.dkey
server> Distribute the device-key to the intended client.
server> The server-key has been saved to C:\Users\<username>\Documents\SATP\srvkey.skey
server> The master-key has been saved to C:\Users\<username>\Documents\SATP\mstkey.mkey
server> Waiting for a connection...
```

Three key files are written to your Documents folder:

| File | Purpose |
|---|---|
| `mstkey.mkey` | Master key — keep secret, used to generate future server keys |
| `srvkey.skey` | Server key — loaded by the server at startup |
| `devkey.dkey` | Device key — distribute this to the intended client |

The server also generates a strong random passphrase that the client must supply to authenticate. In a production deployment this passphrase would be communicated to the device operator through a secure out-of-band channel.

### Step 2 — Start the Client

In Visual Studio, right-click the **Client** project and select **Debug → Start New Instance**. The client prompts for three pieces of information:

```
client> Enter the destination IPv4 address, ex. 192.168.1.1
client> 127.0.0.1
client> Enter the path of the device key:
client> C:\Users\<username>\Documents\SATP\devkey.dkey
client> Enter the login passphrase:
client> UOD)>//jx|(e"p\.fzlY~D\RO:Huz2[i
```

On successful authentication the server confirms the session:

```
server> Authentication success! A client has logged on.
```

The tunnel is now live. All subsequent traffic between client and server is encrypted and authenticated using the negotiated session key. The device key leaf that was consumed during this session is permanently invalidated — replaying the handshake with the same key is cryptographically impossible.

### What Just Happened

```
Client                              Server
  │                                   │
  │── DeviceID + Nonce ──────────────►│  Server looks up device key,
  │                                   │  derives session keys,
  │                                   │  computes session hash hc
  │◄─────────────── Enc(hc) ──────────│
  │                                   │
  │  Client verifies hc               │
  │  Session established              │  Session established
  │                                   │
  │── Enc(DID + PassphraseHash) ─────►│  Server verifies passphrase hash
  │◄─────────────── Enc(SID) ─────────│  Client authenticated
  │                                   │
  │════ Encrypted data channel ══════►│
```

The entire exchange — from the first packet to an authenticated encrypted channel — is complete before a single TLS handshake would have parsed the ClientHello.

---

## Key Hierarchy

```
Master Key (mstkey.mkey)
    └── Server Key (srvkey.skey)  [derived per deployment epoch]
            ├── Device Key 0000  (devkey.dkey)  [1024 one-time-use key leaves]
            ├── Device Key 0001
            ├── Device Key 0002
            └── ...
```

Each device receives one device key file containing a tree of 1,024 one-time-use session keys. Keys are consumed in sequence and zeroed after use. When a device exhausts its tree, a new device key must be provisioned from the server key. The master key is stored offline and used only to regenerate server keys at epoch boundaries.

---

## Deployment Examples

### Instant Contactless Payments
Tap-to-tunnel latency drops from 120 ms to 12 ms. No CA fees. Lost or compromised cards are revoked overnight via branch-epoch rotation — no CRL distribution required.

### Zero-Trust Micro-Services
Internal API calls authenticate in under 0.5 ms. Eliminates TLS CPU overhead and the certificate renewal pipeline entirely.

### Smart-Grid and Massive IoT
Field sensors authenticate using a single SHAKE hash. Reduced cryptographic load extends field-battery lifetime by up to 25%.

### SCADA Retrofits
A 28 kB firmware update delivers quantum-safe tunnels to legacy PLCs. Site re-key is performed via USB epoch bump — no network access to the master key required.

### CubeSat Telemetry
One 256-bit key leaf per day supports a decade-long mission within a fixed CPU and power budget. No certificate uplinks needed.

---

## Building

SATP depends on the **QSC cryptographic library**, a portable, MISRA-aligned implementation of the SHA-3-family primitives, RCS, and SCB.

**Prerequisites**

- CMake 3.15 or newer
- **Windows:** Visual Studio 2022 or newer
- **macOS:** Clang via Xcode or Homebrew
- **Linux:** GCC or Clang

### Windows (Visual Studio)

Open the Visual Studio solution. Ensure library paths are configured as follows:

- SATP library path: `$(SolutionDir)SATP`
- QSC library path: `$(SolutionDir)..\QSC\QSC`

Verify that each Server/Client project **References** the SATP library and that SATP links against QSC. All projects must target the same AVX instruction set under **Configuration Properties → C/C++ → All Options → Enable Enhanced Instruction Set**.

Build order: **QSC → SATP → Server / Client**

### macOS and Linux (Eclipse)

Eclipse project configurations for both platforms are included under `Eclipse/<OS>/project-name/`. Copy the `.project`, `.cproject`, and `.settings` files into each source folder and create corresponding C/C++ projects named **QSC**, **SATP**, **Server**, and **Client**.

Recommended compiler flags by SIMD tier:

| Tier | Flags |
|---|---|
| **AVX** | `-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2` |
| **AVX2** | `-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2` |
| **AVX-512** | `-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes` |

Key flag reference:

| Flag | Purpose |
|---|---|
| `-maes` | AES-NI hardware acceleration (128-bit rounds) |
| `-mvaes` | Vector-AES (512-bit rounds via AVX-512) |
| `-mpclmul` | Carry-less multiply for GF(2ⁿ) |
| `-mrdrnd` | Hardware RNG (RDRAND instruction) |
| `-mbmi2` | Bit-manipulation instructions (PEXT/PDEP) |

Build order: **QSC → SATP → Server / Client**

---

## License

**INVESTMENT INQUIRIES:** QRCS is currently seeking a corporate investor for this technology. Parties interested in licensing or investment should contact: [contact@qrcscorp.ca](mailto:contact@qrcscorp.ca). Visit [qrcscorp.ca](https://www.qrcscorp.ca) for a full inventory of products and services.

**PATENT NOTICE:** One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.

**License and Use Notice (2025–2026)**

All source code and materials in this repository are provided under the **Quantum Resistant Cryptographic Solutions Public Research and Evaluation License (QRCS-PREL), 2025–2026**, unless explicitly stated otherwise.

This license permits **public access and non-commercial research, evaluation, and testing use only**. It does not permit production deployment, operational use, or incorporation into any commercial product or service without a separate written agreement executed with QRCS.

Commercial use, production deployment, supported builds, certified implementations, and integration into products or services require a **separate commercial license and support agreement**.

For licensing inquiries: [licensing@qrcscorp.ca](mailto:licensing@qrcscorp.ca)

*© Quantum Resistant Cryptographic Solutions Corporation, 2026. All rights reserved.*
