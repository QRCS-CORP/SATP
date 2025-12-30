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

#ifndef SATP_KEX_H
#define SATP_KEX_H

#include "satp.h"

/*!
 * \struct satp_kex_client_state
 * \brief The SATP client state structure.
 *
 * \details
 * This structure holds the state information for an SATP client during a key exchange and ongoing communication session.
 */
SATP_EXPORT_API typedef struct satp_kex_client_state
{
	uint8_t dk[SATP_DKEY_SIZE];		/*!< The device derivation key */
	uint8_t kid[SATP_KID_SIZE];		/*!< The device key identity string */
	uint8_t hc[SATP_HASH_SIZE];		/*!< The device session hash */
	uint8_t hp[SATP_HASH_SIZE];		/*!< The device passphrase hash */
	uint8_t stc[SATP_SALT_SIZE];		/*!< The server session salt */
	uint64_t expiration;							/*!< The expiration time, in seconds from epoch */
	uint32_t kidx;									/*!< The current key index */
} satp_kex_client_state;

/*!
 * \struct satp_kex_server_state
 * \brief The SATP server state structure.
 *
 * \details
 * This structure maintains the state of an SATP server connection during the key exchange and secure communication session.
 * It includes the cipher states for both the receive and transmit channels, identity and session hashes, as well as the
 * server derivation key. The structure also holds expiration information and packet sequence numbers for both receiving
 * and transmitting messages. The \c exflag field indicates the current position within the key exchange process.
 */
SATP_EXPORT_API typedef struct satp_kex_server_state
{
	uint8_t hc[SATP_HASH_SIZE];		/*!< The device session hash */
	uint8_t sdk[SATP_SKEY_SIZE];		/*!< The server derivation key */
	uint8_t sid[SATP_SID_SIZE];		/*!< The server identity string */
	uint8_t sp[SATP_HASH_SIZE];		/*!< The passphrase token hash */
	uint8_t stc[SATP_SALT_SIZE];		/*!< The server session salt */
	uint64_t expiration;							/*!< The expiration time in seconds from epoch */
} satp_kex_server_state;

/**
 * \brief Execute the client-side Simplex key exchange.
 *
 * \details
 * This function initiates and completes the Simplex key exchange from the client side.
 * It exchanges the necessary cryptographic keys, verifies the server's identity using the remote verification key,
 * and updates the QSMP connection state with the established session parameters.
 *
 * \param kcs A pointer to the simplex client key exchange state structure.
 * \param cns A pointer to the current QSMP connection state.
 *
 * \return Returns a value of type \c qsmp_errors representing the outcome of the key exchange process.
 *
 * \note This is an internal non-exportable API.
 */
satp_errors satp_kex_client_key_exchange(satp_kex_client_state* kcs, satp_connection_state* cns);

/**
 * \brief Execute the server-side Simplex key exchange.
 *
 * \details
 * This function handles the Simplex key exchange on the server side. It processes the client's connection
 * request, validates the provided cryptographic material, and updates the QSMP connection state with the
 * negotiated session parameters.
 *
 * \param kss A pointer to the simplex server key exchange state structure.
 * \param cns A pointer to the current QSMP connection state.
 *
 * \return Returns a value of type \c qsmp_errors indicating the success or failure of the key exchange.
 *
 * \note This is an internal non-exportable API.
 */
satp_errors satp_kex_server_key_exchange(satp_kex_server_state* kss, satp_connection_state* cns);

#endif
