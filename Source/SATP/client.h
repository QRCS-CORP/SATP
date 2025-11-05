/* 2025 Quantum Resistant Cryptographic Solutions Corporation
 * All Rights Reserved.
 *
 * NOTICE: This software and all accompanying materials are the exclusive 
 * property of Quantum Resistant Cryptographic Solutions Corporation (QRCS).
 * The intellectual and technical concepts contained within this implementation 
 * are proprietary to QRCS and its authorized licensors and are protected under 
 * applicable U.S. and international copyright, patent, and trade secret laws.
 *
 * CRYPTOGRAPHIC STANDARDS:
 * - This software includes implementations of cryptographic algorithms such as 
 *   SHA3, AES, and others. These algorithms are public domain or standardized 
 *   by organizations such as NIST and are NOT the property of QRCS.
 * - However, all source code, optimizations, and implementations in this library 
 *   are original works of QRCS and are protected under this license.
 *
 * RESTRICTIONS:
 * - Redistribution, modification, or unauthorized distribution of this software, 
 *   in whole or in part, is strictly prohibited.
 * - This software is provided for non-commercial, educational, and research 
 *   purposes only. Commercial use in any form is expressly forbidden.
 * - Licensing and authorized distribution are solely at the discretion of QRCS.
 * - Any use of this software implies acceptance of these restrictions.
 *
 * DISCLAIMER:
 * This software is provided "as is," without warranty of any kind, express or 
 * implied, including but not limited to warranties of merchantability or fitness 
 * for a particular purpose. QRCS disclaims all liability for any direct, indirect, 
 * incidental, or consequential damages resulting from the use or misuse of this software.
 *
 * FULL LICENSE:
 * This software is subject to the **Quantum Resistant Cryptographic Solutions 
 * Proprietary License (QRCS-PL)**. The complete license terms are included 
 * in the LICENSE.txt file distributed with this software.
 *
 * Written by: John G. Underhill
 * Contact: contact@qrcscorp.ca
 */

#ifndef SATP_CLIENT_H
#define SATP_CLIENT_H

#include "satpcommon.h"
#include "satp.h"
#include "socketclient.h"

/**
 * \file client.h
 * \brief The SATP client.
 *
 * \details
 * This header defines the client-side functions and state structures for the Symmetric Key Distribution Protocol (SATP).
 * The SATP client is responsible for initiating secure key exchange sessions with an SATP server, managing encryption
 * and decryption of messages, and handling key ratcheting to provide forward secrecy. It supports network connections
 * over both IPv4 and IPv6.
 *
 * The key exchange process in SATP involves several stages, including connection, exchange, establish, and ratchet operations.
 * In each phase, ephemeral keys are derived from pre-shared keys so that even if a device's embedded key is compromised,
 * past communications remain secure.
 *
 * \note All functions and structures defined in this header are part of the internal client implementation.
 */

/*!
 * \brief Send an error code to the remote host.
 *
 * \details
 * This function transmits an SATP error code over the specified socket, thereby informing the remote host
 * of an error condition encountered during communication.
 *
 * \param sock A pointer to the initialized socket structure.
 * \param error The SATP error code to be sent.
 */
SATP_EXPORT_API void satp_client_send_error(const qsc_socket* sock, satp_errors error);

/*!
 * \brief Establish an IPv4 connection and perform the SATP key exchange.
 *
 * \details
 * This function connects to an SATP server over IPv4 and performs the key exchange protocol.
 * It updates the client state with session parameters including cipher states and sequence numbers,
 * and returns the connected socket via the provided socket pointer.
 *
 * \param ckey A pointer to the key state structure.
 * \param address A pointer to the server's IPv4 network address.
 * \param port The server's port number.
 * \param send_func A pointer to the send callback function responsible for transmitting messages.
 * \param receive_callback A pointer to the receive callback function used to process incoming data.
 *
 * \return Returns a value of type \c satp_errors indicating the success or failure of the connection
 *         and key exchange process.
 */
SATP_EXPORT_API satp_errors satp_client_connect_ipv4(satp_device_key* ckey,
	const qsc_ipinfo_ipv4_address* address, uint16_t port,
	void (*send_func)(satp_connection_state*),
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t));

/*!
 * \brief Establish an IPv6 connection and perform the SATP key exchange.
 *
 * \details
 * This function connects to an SATP server over IPv4 and performs the key exchange protocol.
 * It updates the client state with session parameters including cipher states and sequence numbers,
 * and returns the connected socket via the provided socket pointer.
 *
 * \param ckey A pointer to the key state structure.
 * \param address A pointer to the server's IPv6 network address.
 * \param port The server's port number.
 * \param send_func A pointer to the send callback function responsible for transmitting messages.
 * \param receive_callback A pointer to the receive callback function used to process incoming data.
 *
 * \return Returns a value of type \c satp_errors indicating the success or failure of the connection
 *         and key exchange process.
 */
SATP_EXPORT_API satp_errors satp_client_connect_ipv6(satp_device_key* ckey,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(satp_connection_state*),
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t));

/*!
 * \brief Close the remote session and dispose of client resources.
 *
 * \details
 * This function closes the SATP client session by sending an error notification (if necessary) to the remote host,
 * and then disposing of the client state and releasing the associated socket resources.
 *
 * \param cns A pointer to the connection state structure.
 * \param error The SATP error code indicating the reason for closing the session.
 */
SATP_EXPORT_API void satp_client_connection_close(satp_connection_state* cns, satp_errors error);

#endif
