# SATP – Symmetric Authenticated Tunneling Protocol

## Introduction

[![Build](https://github.com/QRCS-CORP/SATP/actions/workflows/build.yml/badge.svg?branch=main)](https://github.com/QRCS-CORP/SATP/actions/workflows/build.yml)
[![CodeQL](https://github.com/QRCS-CORP/SATP/actions/workflows/codeql-analysis.yml/badge.svg)](https://github.com/QRCS-CORP/SATP/actions/workflows/codeql-analysis.yml)
[![CodeFactor](https://www.codefactor.io/repository/github/qrcs-corp/satp/badge)](https://www.codefactor.io/repository/github/qrcs-corp/satp)
[![Platforms](https://img.shields.io/badge/platforms-Linux%20|%20macOS%20|%20Windows-blue)](#)
[![Security Policy](https://img.shields.io/badge/security-policy-blue)](https://github.com/QRCS-CORP/SIAP/security/policy)
[![License: QRCS License](https://img.shields.io/badge/License-QRCS%20License-blue.svg)](https://github.com/QRCS-CORP/SATP/blob/main/License.txt)
[![Language](https://img.shields.io/static/v1?label=Language&message=C%2023&color=blue)](https://www.open-std.org/jtc1/sc22/wg14/www/docs/n3220.pdf)
[![docs](https://img.shields.io/badge/docs-online-brightgreen)](https://qrcs-corp.github.io/SATP/)
[![GitHub release](https://img.shields.io/github/v/release/QRCS-CORP/SATP)](https://github.com/QRCS-CORP/SATP/releases/tag/2025-11-04)
[![GitHub Last Commit](https://img.shields.io/github/last-commit/QRCS-CORP/SATP.svg)](https://github.com/QRCS-CORP/SATP/commits/main)
[![Custom: Standard](https://img.shields.io/static/v1?label=Security%20Standard&message=MISRA&color=blue)](https://misra.org.uk/)
[![Custom: Target](https://img.shields.io/static/v1?label=Target%20Industry&message=Secure%20Infrastructure&color=brightgreen)](#)

**SATP: A Post-Quantum Hierarchical Key Distribution Protocol with Ephemeral Session Keys and Forward Secrecy**
*A certificate-free, quantum-safe tunnel that raises in **two packets** and **under one millisecond**.*

[SATP Help Documentation](https://qrcs-corp.github.io/SATP/)  
[SATP Protocol Specification](https://qrcs-corp.github.io/SATP/pdf/satp_specification.pdf)  
[SATP Summary Document](https://qrcs-corp.github.io/SATP/pdf/satp_summary.pdf)

## Overview

**SATP (Symmetric Authenticated Tunneling Protocol)** is a post-quantum, certificate-free alternative to TLS and SSH that establishes fully authenticated symmetric tunnels in two packets.  
It eliminates the complexity of asymmetric key exchange, certificate authorities, and online trust infrastructure while preserving confidentiality, integrity, and forward secrecy.

SATP is purpose-built for closed, high-assurance environments where **public-key overhead, certificate churn, or quantum risk** are unacceptable.

* **Post-Quantum Security** – Composed exclusively of SHA-3-family primitives and a wide-block Rijndael AEAD stream cipher (`RCS-256`). Resistant to quantum search and factoring attacks.  
* **Two-Packet Handshake** – Client sends a 16-byte device ID and nonce; server responds with an authenticated hash. Tunnel established in \< 1 ms.  
* **Certificate-Free Identity** – 16-byte identity encodes *domain · branch · device · key-index*. No X.509, CRLs, or OCSP.  
* **Forward-Secrecy-by-Consumption** – Each session consumes a one-time key derived from a hierarchical tree. Past sessions remain undecryptable even after key exposure.  
* **Deterministic, Verifiable Security** – Every handshake, key derivation, and authentication event can be reproduced and audited from deterministic SHAKE outputs.  
* **Tiny Footprint** – \< 30 kB flash / \< 4 kB RAM; deployable on Cortex-M0+, PLCs, CubeSats, and embedded controllers.  

SATP delivers the cryptographic assurance of TLS 1.3 with constant-time operations, zero certificates, and predictable sub-millisecond setup latency.


## 2  Cryptographic Core

| Primitive              | Role                          | Quantum Margin               |
|------------------------|--------------------------------|------------------------------|
| **RCS-256**            | Stream cipher + AEAD           | ≥ 2¹²⁸ Grover-bounded        |
| **SHAKE-256 / cSHAKE-256** | Key derivation + hashing     | ≥ 2¹²⁸ pre-image             |
| **KMAC-256**           | Packet authentication          | Tag-forgery ≤ 2⁻¹²⁸          |
| **SCB-KDF**            | Password hardening / auth      | ≥ 2²⁰ CPU·MiB per guess      |


## 3  Deployment Snapshots

### 3.1  Instant Contactless Payments
Tap-to-tunnel latency drops from 120 ms → 12 ms. No CA fees. Lost cards revoked overnight via branch-epoch rotation.

### 3.2  Zero-Trust Micro-Services
Internal API calls authenticate in \< 0.5 ms. 65 % TLS CPU reclaimed; certificate pipeline removed entirely.

### 3.3  Smart-Grid & Massive IoT
Sensors authenticate using a single SHAKE hash. Field-battery lifetime +25 %.

### 3.4  SCADA Retrofits
28 kB firmware upgrade delivers quantum-safe tunnels to legacy PLCs. Site re-key via USB epoch bump.

### 3.5  CubeSat Telemetry
One 256-bit key per day ⇒ decade-long mission with fixed CPU budget and no certificate uplinks.


## Compilation

SATP depends on the **QSC cryptographic library**, a portable, MISRA-aligned implementation of SHA-3-family primitives, RCS, and SCB.  
QSC builds cleanly across **Windows**, **macOS**, and **Linux** using [CMake](https://cmake.org/), with hardware acceleration support for AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake** 3.15 or newer  
- **Windows:** Visual Studio 2022 or newer  
- **macOS:** Clang via Xcode or Homebrew  
- **Ubuntu:** GCC or Clang  


### Building the SATP library and Client/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the **SATP**, **Server**, and **Client** projects.  
Extract the source, open the Server and Client solutions, and ensure library paths are set correctly:  

- **SATP library** path: `$(SolutionDir)SATP`  
- **QSC library** path: `$(SolutionDir)..\QSC\QSC`  

Verify that each Server/Client project **References** the SATP library and that SATP links to QSC.  
All projects should target the same AVX instruction set under  
**Configuration Properties → C/C++ → All Options → Enable Enhanced Instruction Set**.  
Compile order: QSC → SATP → Server/Client.  

#### macOS / Ubuntu (Eclipse)

SATP and QSC projects include Eclipse configurations for both Ubuntu and macOS.  
Copy the appropriate `.project`, `.cproject`, and `.settings` files from  
`Eclipse/<OS>/project-name/` into each source folder.  

Create new C/C++ projects named **QSC**, **SATP**, **Server**, and **Client**, importing the corresponding source directories.  
Eclipse will detect build settings automatically; adjust compiler (GCC/Clang) as required.  

The default configurations use minimal flags and no enhanced intrinsics.  
Example flag sets:

- **AVX Support:** `-msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2`  
- **AVX2 Support:** `-msse2 -mavx -mavx2 -maes -mpclmul -mrdrnd -mbmi2`  
- **AVX-512 Support:** `-msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes`  

**Key flags:**  
- `-maes` AES-NI (128-bit rounds)  
- `-mvaes` Vector-AES (512-bit rounds)  
- `-mpclmul` Carry-less multiply for GF(2ⁿ)  
- `-mrdrnd` Hardware RNG (RDRAND)  
- `-mbmi2` Bit-manipulation instructions (PEXT/PDEP)  

Compile QSC, then SATP, followed by the Server and Client binaries.  
SATP produces small, deterministic binaries suitable for both desktop and embedded targets.


## License

ACQUISITION INQUIRIES:
QRCS is currently seeking a corporate acquirer for this technology.
Parties interested in exclusive licensing or acquisition should contact: contact@qrcscorp.ca

PATENT NOTICE:
One or more patent applications (provisional and/or non-provisional) covering aspects of this software have been filed with the United States Patent and 
Trademark Office (USPTO). Unauthorized use may result in patent infringement liability.  

QRCS-PL private License. See license file for details.  
Software is copyrighted and SATP is patent pending.
Written by John G. Underhill, under the QRCS-PL license, see the included license file for details. 
Not to be redistributed or used commercially without the author's expressed written permission. 
_All rights reserved by QRCS Corp. 2025._

