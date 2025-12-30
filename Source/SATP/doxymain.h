/* 2025-2026 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE:
 * This software and all accompanying materials are the exclusive property of
 * Quantum Resistant Cryptographic Solutions Corporation (QRCS). The intellectual
 * and technical concepts contained herein are proprietary to QRCS and are
 * protected under applicable Canadian, U.S., and international copyright,
 * patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC ALGORITHMS AND IMPLEMENTATIONS:
 * - This software includes implementations of cryptographic primitives and
 *   algorithms that are standardized or in the public domain, such as AES
 *   and SHA-3, which are not proprietary to QRCS.
 * - This software also includes cryptographic primitives, constructions, and
 *   algorithms designed by QRCS, including but not limited to RCS, SCB, CSX, QMAC, and
 *   related components, which are proprietary to QRCS.
 * - All source code, implementations, protocol compositions, optimizations,
 *   parameter selections, and engineering work contained in this software are
 *   original works of QRCS and are protected under this license.
 *
 * LICENSE AND USE RESTRICTIONS:
 * - This software is licensed under the Quantum Resistant Cryptographic Solutions
 *   Public Research and Evaluation License (QRCS-PREL), 2025-2026.
 * - Permission is granted solely for non-commercial evaluation, academic research,
 *   cryptographic analysis, interoperability testing, and feasibility assessment.
 * - Commercial use, production deployment, commercial redistribution, or
 *   integration into products or services is strictly prohibited without a
 *   separate written license agreement executed with QRCS.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 *
 * EXPERIMENTAL CRYPTOGRAPHY NOTICE:
 * Portions of this software may include experimental, novel, or evolving
 * cryptographic designs. Use of this software is entirely at the user's risk.
 *
 * DISCLAIMER:
 * THIS SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO WARRANTIES OF MERCHANTABILITY, FITNESS
 * FOR A PARTICULAR PURPOSE, SECURITY, OR NON-INFRINGEMENT. QRCS DISCLAIMS ALL
 * LIABILITY FOR ANY DIRECT, INDIRECT, INCIDENTAL, OR CONSEQUENTIAL DAMAGES
 * ARISING FROM THE USE OR MISUSE OF THIS SOFTWARE.
 *
 * FULL LICENSE:
 * This software is subject to the Quantum Resistant Cryptographic Solutions
 * Public Research and Evaluation License (QRCS-PREL), 2025-2026. The complete license terms
 * are provided in the accompanying LICENSE file or at https://www.qrcscorp.ca.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef SATP_DOXYMAIN_H
#define SATP_DOXYMAIN_H

/**
 * \mainpage Symmetric Authenticated Tunneling Protocol (SATP)
 *
 * \section introduction Introduction
 *
 * The Symmetric Authenticated Tunneling Protocol (SATP) is a next-generation
 * secure communications framework designed to establish cryptographically
 * authenticated and confidential tunnels using only symmetric primitives.
 * SATP eliminates the reliance on online public-key infrastructures (PKI)
 * and ephemeral asymmetric exchanges, achieving equivalent levels of
 * confidentiality, integrity, and forward secrecy through pre-provisioned
 * hierarchical symmetric keys and authenticated encryption.
 *
 * SATP is optimized for environments where centralized trust authorities
 * exist, such as industrial control, secure embedded systems, field
 * communications, and closed network infrastructures. Its lightweight design
 * enables high-speed, low-latency encryption without the computational cost
 * of traditional hybrid or asymmetric protocols.
 *
 * \section problem Statement of the Problem
 *
 * Traditional secure tunneling protocols such as TLS, SSH, and IKE rely on
 * asymmetric key exchange mechanisms and certificate-based authentication.
 * These systems present challenges in environments where:
 *
 * - Certificate issuance and revocation infrastructure is unavailable.
 * - Devices must operate offline or under intermittent connectivity.
 * - Long-term cryptographic independence from public-key systems is required.
 *
 * In such cases, asymmetric operations increase computational cost and
 * complexity, while their key lifecycles remain vulnerable to compromise or
 * certificate mismanagement. SATP was designed to provide a provably secure
 * alternative in these constrained or regulated environments.
 *
 * \section satp_solution The SATP Solution
 *
 * SATP uses a hierarchical symmetric key structure combined with ephemeral
 * per-session derivations to establish a tunnel with full AEAD protection.
 * The protocol consists of two phases:
 *
 * - **Handshake Phase:** The client and server exchange nonces and derive
 *   session transmit and receive keys (*Kt*, *Kr*) using SHAKE256-based
 *   expansion from a pre-provisioned device key (*Kc,i*). A session hash
 *   confirms mutual possession of the shared key material.
 * - **Encrypted Channel Phase:** All communication occurs through an AEAD
 *   stream cipher (RCS or AES-GCM). Packet headers are serialized and
 *   included as associated data to bind sequence numbers and timestamps
 *   into the authentication domain.
 *
 * The server then performs optional client authentication using a hardened
 * SCB (SHAKE Cost-Based) passphrase verification. This process occurs after
 * the encrypted channel is active, ensuring that credentials are never
 * exposed in plaintext.
 *
 * \section hierarchy Hierarchical Key Structure
 *
 * SATP employs a secure hierarchical key derivation system:
 *
 * - A master domain key (*K₀*) generates branch keys (*Kb*).
 * - Each branch key derives device keys (*Kc,i*), each unique to a device.
 * - Device keys are single-use: they are burned after one session to ensure
 *   perfect forward secrecy.
 *
 * Session keys (*Kt* and *Kr*) are further derived from *Kc,i* and a mixed
 * nonce (*Nh = SHAKE256(Nh_c ‖ Nh_s)*), ensuring bidirectional key
 * independence. This structure isolates compromise to a single device and
 * session, maintaining network-wide containment.
 *
 * \section advantages Advantages of SATP
 *
 * - **Post-Quantum Symmetric Security:** Uses SHAKE256 and RCS, offering
 *   resilience against quantum adversaries within symmetric bounds.
 * - **Forward Secrecy:** Each session uses a unique one-time device key and
 *   nonce, preventing retrospective decryption.
 * - **Low Computational Cost:** No elliptic-curve or modular exponentiation
 *   operations; handshake completes in two messages.
 * - **Replay Resistance:** Timestamp and sequence enforcement validated before
 *   decryption.
 * - **Implementation Simplicity:** Compact and MISRA-compliant codebase suitable
 *   for embedded and industrial systems.
 *
 * \section applications Applications
 *
 * SATP is applicable to:
 *
 * - Industrial and SCADA networks requiring secure but deterministic links.
 * - Field-deployed or mobile systems operating offline from a central authority.
 * - Embedded devices with hardware-enrolled symmetric credentials.
 * - High-performance servers or IoT gateways needing rapid, low-overhead tunnels.
 * - Environments where PKI management or asymmetric cryptography is impractical.
 *
 * \section conclusion Conclusion
 *
 * SATP provides a fully symmetric, authenticated encryption framework with
 * forward secrecy and high operational efficiency. Its reliance on hierarchical
 * symmetric derivations instead of online public-key exchanges allows
 * deployment in closed or offline systems while preserving the cryptographic
 * strength and integrity of traditional secure tunnels. By integrating SCB-based
 * authentication, timestamp-bound replay protection, and deterministic AEAD
 * operations, SATP achieves strong, scalable, and verifiable tunnel security
 * within a lightweight implementation footprint.
 *
 * \section license_sec License
 *
 * QRCS-PL private license. See license file for details.
 * All rights reserved by QRCS Corporation, copyrighted and patents pending.
 *
 * \author John G. Underhill
 * \date 2025-11-04
 */

#endif
