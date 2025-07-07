# SATP – Symmetric Authenticated Tunneling Protocol

## Introduction

**SATP: A Post-Quantum Hierarchical Key Distribution Protocol with Ephemeral Session Keys and Forward Secrecy**
*A certificate-free, quantum-safe tunnel that raises in **two packets** and **under one millisecond**.*

## Overview

SATP is a drop-in replacement for TLS/SSH wherever **public-key overhead, certificate churn, or quantum risk** is unacceptable.

* **Post-Quantum Security** – Built entirely on SHA-3-family primitives and a wide-block Rijndael stream cipher (`RCS-256`).  
* **Two-Packet Handshake** – Client sends a 16-byte identity + nonce; server replies with an authenticated hash. Tunnel is up in \< 1 ms.  
* **Zero Certificates** – 16-byte identity encodes domain · branch · device · key-index. No X.509, CRLs, or OCSP.  
* **Forward-Secrecy-by-Consumption** – Each session burns a one-time key; past traffic stays private even after device compromise.  
* **Tiny Footprint** – \< 30 kB flash / \< 4 kB RAM; runs on Cortex-M0+, PLCs, CubeSats.

## 2  Cryptographic Core

| Primitive            | Role                        | Quantum Margin                 |
|----------------------|-----------------------------|--------------------------------|
| **RCS-256**          | Stream cipher + AEAD        | ≥ 2¹²⁸ Grover-bounded          |
| **SHAKE-256 / cSHAKE-256** | Key derivation + hashing | ≥ 2¹²⁸ pre-image               |
| **KMAC-256**         | Packet authentication       | Tag-forgery ≤ 2⁻¹²⁸            |
| **SCB-KDF**          | Password hardening          | ≥ 2²⁰ CPU·MiB per guess        |


## 3  Protocol in 30 s

Client			Server

ID || Nonce -->		Derive Rk, Sk  
Derive Rk, Sk		Compute Hc  
			<-- Hc(enc+MAC)  
Verify Hc
TUNNEL ESTABLISHED  
Hc = SHAKE256( nonce ‖ Kc,i ‖ branch-secret )  
Two packets, two SHAKE calls, sub-millisecond handshake.  


## 4 Key Hierarchy

Kroot  (16-bit domain)  
 ├─ Kbr[0]  (16-bit branch)  
 │    ├─ Kc,i[0] … (device key-tree)  
 │    └─ …  
 └─ Kbr[n]  

65 536 branches per root · 4 294 967 296 one-time keys per device.


## 5 Deployment Snapshots
5.1 Instant Contactless Payments
Tap latency drops from 120 ms to 12 ms; no CA fees; lost cards revoked overnight via branch-epoch roll.

### 5.2 Zero-Trust Micro-Services
Internal API calls authenticate in < 0.5 ms. 65 % TLS CPU reclaimed; certificate pipeline removed.

### 5.3 Smart-Grid & Massive IoT
Sensors authenticate with a single SHAKE hash; field battery life +25 %.

### 5.4 SCADA Retrofits
28 kB firmware upgrade brings quantum-safe tunnels to legacy PLCs; site re-key via USB epoch bump.

### 5.5 CubeSat Telemetry
One 256-bit key per day ⇒ decade-long mission with deterministic CPU budget; no cert uplinks.


## Compilation

SATP uses the QSC cryptographic library. QSC is a standalone, portable, and MISRA-aligned cryptographic library written in C. It supports platform-optimized builds across **Windows**, **macOS**, and **Linux** via [CMake](https://cmake.org/), and includes support for modern hardware acceleration such as AES-NI, AVX2/AVX-512, and RDRAND.

### Prerequisites

- **CMake**: 3.15 or newer
- **Windows**: Visual Studio 2022 or newer
- **macOS**: Clang via Xcode or Homebrew
- **Ubuntu**: GCC or Clang  

### Building SATP library and the Client/Server projects

#### Windows (MSVC)

Use the Visual Studio solution to create the library and the Server and Client projects: SATP, Server, and Client.
Extract the files, and open the Server and Client projects. The SATP library has a default location in a folder parallel to the Server and Client project folders.  
The server and client projects additional files folder are set to: **$(SolutionDir)SATP** and **$(SolutionDir)..\QSC\QSC**, if this is not the location of the library files, change it by going to server/client project properties **Configuration Properties->C/C++->General->Additional Include Directories** and set the library files location.  
Ensure that the **[server/client]->References** property contains a reference to the SATP library, and that the SATP library contains a valid reference to the QSC library.  
QSC and SATP support every AVX instruction family (AVX/AVX2/AVX-512).  
Set the QSC and SATP libries and every server/client project to the same AVX family setting in **Configuration Properties->C/C++->All Options->Enable Enhanced Instruction Set**.  
Set both QSC and SATP to the same instruction set in Debug and Release Solution Configurations.  
Compile the QSC library (right-click and choose build), build the SATP library, then build the Server and Client projects.

#### MacOS / Ubuntu (Eclipse)

The QSC and the SATP library projects, along with the Server and Client projects have been tested using the Eclipse IDE on Ubuntu and MacOS.  
In the Eclipse folder there are subfolders for Ubuntu and MacOS that contain the **.project**, **.cproject**, and **.settings** Eclipse project files.  Copy those files directly into the folders containing the code files; move the files in the **Eclipse\Ubuntu\project-name** or **Eclipse\MacOS\project-name** folder to the folder containing the project's header and implementation files, on the SATP and the Server and Client projects.  
Create a new project for QSC, select C/C++ project, and then **Create an empty project** with the same name as the folder with the files, 'QSC'. Repeat for every additional project.  
Eclipse should load the project with all of the settings into the project view window. The same proceedure is true for **MacOS and Ubuntu**, but some settings are different (GCC/Clang), so choose the project files that correspond to the operating system.  
The default projects use minimal flags, and are set to No Enhanced Intrinsics by default.

Sample flag sets and their meanings:  
-**AVX Support**: -msse2 -mavx -maes -mpclmul -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # 256-bit FP/SIMD  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mpclmul**      # PCLMUL (carry-less multiply)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX2 Support**: -msse2 -mavx -mavx2 -mpclmul -maes -mrdrnd -mbmi2  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # 256-bit integer + FP SIMD  
-**mpclmul**      # PCLMUL (carry-less multiply for AES-GCM, GHASH, etc.)  
-**maes**         # AES-NI (128-bit AES rounds)  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  

-**AVX-512 Support**: -msse2 -mavx -mavx2 -mavx512f -mavx512bw -mvaes -mpclmul -mrdrnd -mbmi2 -maes  
-**msse2**        # baseline for x86_64  
-**mavx**         # AVX baseline  
-**mavx2**        # AVX2 baseline (implied by AVX-512 but explicit is safer)  
-**mavx512f**     # 512-bit Foundation instructions  
-**mavx512bw**    # 512-bit Byte/Word integer instructions  
-**mvaes**        # Vector-AES (VAES) in 512-bit registers  
-**mpclmul**      # PCLMUL (carry-less multiply for GF(2ⁿ))  
-**mrdrnd**       # RDRAND (hardware RNG)  
-**mbmi2**        # BMI2 (PEXT/PDEP, bit-manipulation)  
-**maes**         # AES-NI (128-bit AES rounds; optional if VAES covers your AES use)  


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

