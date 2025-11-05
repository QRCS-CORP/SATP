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

#ifndef SATP_H
#define SATP_H

#include "satpcommon.h"
#include "logger.h"
#include "sha3.h"
#include "socket.h"
#include "socketclient.h"

/**
* \file satp.h
* \brief SATP support header
* Common defined parameters and functions of the SATP client and server implementations.
*/

/*!
* \def SATP_USE_RCS_ENCRYPTION
* \brief If the RCS encryption option is chosen SATP uses the more modern RCS stream cipher with KMAC/QMAC authentication.
* The default symmetric cipher/authenticator is AES-256/GCM (GMAC Counter Mode) NIST standardized per SP800-38a.
*/
#define SATP_USE_RCS_ENCRYPTION

#if defined(SATP_USE_RCS_ENCRYPTION)
#	include "rcs.h"
#	define satp_cipher_state qsc_rcs_state
#	define satp_cipher_dispose qsc_rcs_dispose
#	define satp_cipher_initialize qsc_rcs_initialize
#	define satp_cipher_keyparams qsc_rcs_keyparams
#	define satp_cipher_set_associated qsc_rcs_set_associated
#	define satp_cipher_transform qsc_rcs_transform
#else
#	include "aes.h"
#	define satp_cipher_state qsc_aes_gcm256_state
#	define satp_cipher_dispose qsc_aes_gcm256_dispose
#	define satp_cipher_initialize qsc_aes_gcm256_initialize
#	define satp_cipher_keyparams qsc_aes_keyparams
#	define satp_cipher_set_associated qsc_aes_gcm256_set_associated
#	define satp_cipher_transform qsc_aes_gcm256_transform
#endif

/**
 * \file satp.h
 * \brief The SATP settings.
 *
 * \details
 * This header defines the configuration parameters, macros, and constants used in the
 * Symmetric Key Distribution Protocol (SATP). SATP is designed to securely distribute symmetric keys
 * between a master, server, device, and session while providing forward secrecy. The protocol employs
 * ephemeral keys for each session, ensuring that even if a device or server key is compromised, past
 * communications remain secure.
 *
 * SATP is structured into several phases:
 *
 * - **Connect Request:** The client sends its identity string, configuration string, and a random session token
 *   to the server. The client computes a device session hash from its device ID, configuration, and token.
 *
 * - **Connect Response:** The server verifies the client's configuration and key identity, generates its own session token,
 *   computes its session hash, and responds with its server ID, configuration string, and token.
 *
 * - **Exchange Request:** The client generates a secret random token key, derives encryption and MAC keys using a combination
 *   of its device session hash and embedded key, and then encrypts and MACs the secret token before sending it to the server.
 *
 * - **Exchange Response:** The server verifies the MAC, decrypts the token, and derives the receive channel cipher key using
 *   its embedded key and the client's device session hash.
 *
 * - **Establish Request:** The client verifies the server's token hash and, if valid, encrypts its key identity to send to the server.
 *
 * - **Establish Response:** The server decrypts and verifies the key identity, then re-encrypts and echoes it back.
 *
 * - **Establish Verify:** The client decrypts the echoed key identity and verifies it, thereby finalizing the established session.
 *
 * In addition, this header defines sizes for configuration strings, error messages, expiration fields, packet headers,
 * keepalive messages, and various key and identity fields, ensuring consistency across SATP implementations.
 *
 * \note The SATP settings provided herein are critical for the proper operation and security of the key distribution
 * process.
 */

 /*!
 * \def SATP_CLIENT_PASSWORD_MAX
 * \brief The client passphrase maximum string length
 */
#define SATP_CLIENT_PASSWORD_MAX 256U

 /*!
 * \def SATP_CLIENT_USERNAME_MAX
 * \brief The client username maximum string length
 */
#define SATP_CLIENT_USERNAME_MAX 256U

 /*!
 * \def SATP_CONNECTIONS_INIT
 * \brief The intitial SATP connections queue size
 */
#define SATP_CONNECTIONS_INIT 1000U

 /*!
 * \def SATP_CONNECTIONS_MAX
 * \brief The maximum number of connections
 */
#define SATP_CONNECTIONS_MAX 50000U

/*!
 * \def SATP_CONFIG_SIZE
 * \brief The size of the protocol configuration string.
 */
#define SATP_CONFIG_SIZE 25U

/*!
 * \def SATP_ERROR_SIZE
 * \brief The size of a system error message.
 */
#define SATP_ERROR_SIZE 1U

/*!
 * \def SATP_EXPIRATION_SIZE
 * \brief The size (in bytes) of the expiration field.
 */
#define SATP_EXPIRATION_SIZE 8U

/*!
 * \def SATP_HASH_SIZE
 * \brief The SATP hash size in bytes.
 */
#define SATP_HASH_SIZE 32U

/*!
 * \def SATP_HEADER_SIZE
 * \brief The SATP packet header size in bytes.
 */
#define SATP_HEADER_SIZE 21U

/*!
 * \def SATP_KEEPALIVE_MESSAGE
 * \brief The size (in bytes) of the keep alive integer message.
 */
#define SATP_KEEPALIVE_MESSAGE 8U

/*!
 * \def SATP_KEEPALIVE_STRING
 * \brief The keep alive string size in bytes.
 */
#define SATP_KEEPALIVE_STRING 20U

/*!
 * \def SATP_KEEPALIVE_TIMEOUT
 * \brief The keep alive timeout in milliseconds (5 minutes).
 */
#define SATP_KEEPALIVE_TIMEOUT (300U * 1000U)

/*!
 * \def SATP_KEY_TREE_COUNT
 * \brief The SATP key tree count.
 */
#define SATP_KEY_TREE_COUNT 1024

/*!
 * \brief The SATP configuration string for 256-bit security.
 */
#if defined(SATP_USE_RCS_ENCRYPTION)
#	define SATP_MACTAG_SIZE 32U
#else
#	define SATP_MACTAG_SIZE 16U
#endif

/*!
 * \def SATP_MESSAGE_SIZE
 * \brief The message size (in bytes) used during a communications session.
 */
#define SATP_MESSAGE_SIZE 1024U

/*!
 * \def SATP_MESSAGE_MAX
 * \brief The maximum message size in bytes (may exceed MTU).
 */
#define SATP_MESSAGE_MAX (SATP_MESSAGE_SIZE + SATP_HEADER_SIZE)

 /*!
 * \def SATP_CONNECTION_MTU
 * \brief The SATP packet buffer size
 */
#define SATP_CONNECTION_MTU 1500U

/*!
 * \def SATP_NONCE_SIZE
 * \brief The nonce size in bytes
 */
#if defined(SATP_USE_RCS_ENCRYPTION)
#	define SATP_NONCE_SIZE 32U
#else
#	define SATP_NONCE_SIZE 16U
#endif

/*!
 * \def SATP_SALT_SIZE
 * \brief The SATP salt size in bytes.
 */
#define SATP_SALT_SIZE 32U

/*!
 * \def SATP_SERVER_PORT
 * \brief The default SATP server port number.
 */
#define SATP_SERVER_PORT 2701U

/*!
 * \def SATP_SEQUENCE_TERMINATOR
 * \brief The sequence number of a packet that closes a connection.
 */
#define SATP_SEQUENCE_TERMINATOR 0xFFFFFFFFUL

/*!
 * \brief The SATP configuration string for 256-bit security.
 */
#if defined(SATP_USE_RCS_ENCRYPTION)
	static const char SATP_CONFIG_STRING[SATP_CONFIG_SIZE + 1U] = "r01-satp-rcs256-keccak256";
#else
	static const char SATP_CONFIG_STRING[SATP_CONFIG_SIZE + 1U] = "r02-satp-aes256-keccak256";
#endif

/* Exchange thresholds */

/*!
 * \def SATP_KEY_DURATION_DAYS
 * \brief The number of days a key remains valid.
 */
#define SATP_KEY_DURATION_DAYS 365U

/*!
 * \def SATP_PACKET_TIME_THRESHOLD
 * \brief The maximum number of seconds a packet is considered valid.
 *
 * \details
 * On networks with a shared (NTP) time source, this may be set to as low as 1 second.
 * On exterior networks, it should be adjusted (typically between 30 and 100 seconds) to account for clock differences.
 */
#define SATP_PACKET_TIME_THRESHOLD 60U

/*!
 * \def SATP_KEY_DURATION_SECONDS
 * \brief The number of seconds a key remains valid.
 */
#define SATP_KEY_DURATION_SECONDS (SATP_KEY_DURATION_DAYS * 24U * 60U * 60U)

/* Key identity elements */

/*!
 * \def SATP_BRANCH_ID_SIZE
 * \brief Branch ID size in bytes.
 */
#define SATP_BRANCH_ID_SIZE 2U

/*!
 * \def SATP_DOMAIN_ID_SIZE
 * \brief Domain (Master) ID size in bytes.
 */
#define SATP_DOMAIN_ID_SIZE 2U

/*!
 * \def SATP_DEVICE_ID_SIZE
 * \brief Device ID size in bytes.
 */
#define SATP_DEVICE_ID_SIZE 4U

/*!
 * \def SATP_EPOCH_SIZE
 * \brief Epoch class size in bytes.
 */
#define SATP_EPOCH_SIZE 2U

 /*!
 * \def SATP_ERROR_MESSAGE_SIZE
 * \brief The packet error message size
 */
#define SATP_ERROR_MESSAGE_SIZE 1U

 /*!
 * \def SATP_ERROR_SEQUENCE
 * \brief The packet error sequence number
 */
#define SATP_ERROR_SEQUENCE 0xFF00000000000000ULL

 /*!
 * \def SATP_FLAG_SIZE
 * \brief The packet flag size
 */
#define SATP_FLAG_SIZE 1

/*!
 * \def SATP_KEY_ID_SIZE
 * \brief Key ID size in bytes.
 */
#define SATP_KEY_ID_SIZE 4U

/*!
 * \def SATP_SERVICE_ID_SIZE
 * \brief Service ID size in bytes.
 */
#define SATP_SERVICE_ID_SIZE 2U

/*!
 * \def SATP_DID_SIZE
 * \brief The full sub-key ID size in bytes.
 */
#define SATP_DID_SIZE (SATP_DOMAIN_ID_SIZE + SATP_BRANCH_ID_SIZE + SATP_EPOCH_SIZE + SATP_SERVICE_ID_SIZE + SATP_DEVICE_ID_SIZE)

/*!
 * \def SATP_MID_SIZE
 * \brief The master key identity size in bytes.
 */
#define SATP_MID_SIZE (SATP_DOMAIN_ID_SIZE)

/*!
 * \def SATP_SID_SIZE
 * \brief The server ID size in bytes.
 */
#define SATP_SID_SIZE (SATP_DOMAIN_ID_SIZE + SATP_BRANCH_ID_SIZE)

/*!
 * \def SATP_KID_SIZE
 * \brief The key ID size in bytes.
 */
#define SATP_KID_SIZE (SATP_DID_SIZE + SATP_KEY_ID_SIZE)

/* key sizes */

/*!
 * \def SATP_DKEY_SIZE
 * \brief The client key size in bytes.
 */
#define SATP_DKEY_SIZE 32U

/*!
 * \def SATP_MKEY_SIZE
 * \brief The master key size in bytes.
 */
#define SATP_MKEY_SIZE 32U

/*!
 * \def SATP_SKEY_SIZE
 * \brief The server key size in bytes.
 */
#define SATP_SKEY_SIZE 32U

/*!
 * \def SATP_KTREE_SIZE
 * \brief	The key tree size in bytes.
 */
#define SATP_KTREE_SIZE (SATP_DKEY_SIZE * SATP_KEY_TREE_COUNT)

/*!
 * \def SATP_DKEY_ENCODED_SIZE
 * \brief The serialized device key size in bytes.
 */
#define SATP_DKEY_ENCODED_SIZE (SATP_KID_SIZE + SATP_SKEY_SIZE + SATP_EXPIRATION_SIZE + (SATP_DKEY_SIZE * SATP_KEY_TREE_COUNT))

/*!
 * \def SATP_MKEY_ENCODED_SIZE
 * \brief serialized master key size in bytes.
 */
#define SATP_MKEY_ENCODED_SIZE (SATP_MKEY_SIZE + SATP_MID_SIZE + SATP_EXPIRATION_SIZE)

/*!
 * \def SATP_SKEY_ENCODED_SIZE
 * \brief serialized server key size in bytes.
 */
#define SATP_SKEY_ENCODED_SIZE (SATP_SKEY_SIZE + SATP_SKEY_SIZE + SATP_SID_SIZE + SATP_EXPIRATION_SIZE)

/*!
 * \def SATP_STOK_SIZE
 * \brief The session token size in bytes.
 */
#define SATP_STOK_SIZE 32U

/* error code strings */

/** \cond */
#define SATP_ERROR_STRING_DEPTH 22U
#define SATP_ERROR_STRING_WIDTH 128U

static const char SATP_ERROR_STRINGS[SATP_ERROR_STRING_DEPTH][SATP_ERROR_STRING_WIDTH] =
{
	"No error was detected",
	"The keep alive check failed",
	"The cipher authentication has failed",
	"The communications channel has failed",
	"The device could not make a connection to the remote host",
	"The decryption authentication has failed",
    "The device identity is unrecognized",
	"The transmission failed at the key exchange establish phase",
	"The input provided is invalid",
	"The keep alive has expired with no response",
	"The key exchange authentication has failed",
    "The SATP public key has expired",
	"The key identity is not recognized",
	"The packet keep alive is invalid",
    "The packet was received out of sequence",
    "The random generator has failed",
    "The receiver failed at the network layer",
    "The transmitter failed at the network layer",
    "The protocol string was not recognized",
	"The packets sequence number is out of sync",
    "The expected data could not be verified",
    "A general failure occurred",
};
/** \endcond */

/*!
* \def SATP_MESSAGE_STRING_DEPTH
* \brief The depth of the SATP message string array
*/
#define SATP_MESSAGE_STRING_DEPTH 22U
/*!
* \def SATP_MESSAGE_STRING_WIDTH
* \brief The width of each SATP message string
*/
#define SATP_MESSAGE_STRING_WIDTH 128U

/** \cond */
static const char SATP_MESSAGE_STRINGS[SATP_MESSAGE_STRING_DEPTH][SATP_MESSAGE_STRING_WIDTH] =
{
	"The operation completed succesfully.",
	"The socket server accept function failed.",
	"The listener socket listener could not connect.",
	"The listener socket could not bind to the address.",
	"The listener socket could not be created.",
	"The server is connected to remote host: ",
	"The socket receive function failed.",
	"The server had a memory allocation failure.",
	"The key exchange has experienced a failure.",
	"The server has disconnected from the remote host: ",
	"The server has disconnected the client due to an error",
	"The server has had a socket level error: ",
	"The server has reached the maximum number of connections",
	"The server listener socket has failed.",
	"The server has run out of socket connections",
	"The message decryption has failed",
	"The keepalive function has failed",
	"The keepalive period has been exceeded",
	"The connection failed or was interrupted",
	"The function received an invalid request",
	"The host encountered an error: "
};
/** \endcond */

/*!
 * \enum satp_errors
 * \brief The SATP error values.
 * This enumeration defines the error codes returned by SATP functions.
 */
SATP_EXPORT_API typedef enum satp_errors
{
	satp_error_none = 0x00U,					/*!< No error was detected */
	satp_error_accept_fail = 0x01,				/*!< The socket accept failed */
	satp_error_authentication_failure = 0x02U,	/*!< The authentication failed */
	satp_error_authentication_success = 0x03U,	/*!< The authentication succeeded */
	satp_erroe_listen_fail = 0x04U,				/*!< The listener socket could not connect */
	satp_error_allocation_failure = 0x05U,		/*!< The memory could not be allocated */
	satp_error_bad_keep_alive = 0x06U,			/*!< The keep alive check failed */
	satp_error_cipher_auth_failure = 0x07U,		/*!< The cipher authentication has failed */
	satp_error_channel_down = 0x08U,			/*!< The communications channel has failed */
	satp_error_connection_failure = 0x09U,		/*!< The device could not make a connection to the remote host */
	satp_error_decryption_failure = 0x0AU,		/*!< The decryption authentication has failed */
	satp_error_device_unrecognized = 0x0BU,		/*!< The device identity is unrecognized */
	satp_error_establish_failure = 0x0CU,		/*!< The transmission failed at the key exchange establish phase */
	satp_error_hosts_exceeded = 0x0DU,			/*!< The server has run out of socket connections */
	satp_error_invalid_input = 0x0EU,			/*!< The input provided is invalid */
	satp_error_invalid_request = 0x0FU,			/*!< The packet flag was unexpected */
	satp_error_keep_alive_expired = 0x10U,		/*!< The keep alive has expired with no response */
	satp_error_kex_auth_failure = 0x11U,		/*!< The key exchange authentication has failed */
	satp_error_key_expired = 0x12U,				/*!< The SATP public key has expired */
	satp_error_key_not_recognized = 0x13U,		/*!< The key identity is not recognized */
	satp_error_listener_fail = 0x14U,			/*!< The listener function failed to initialize */
	satp_error_message_time_invalid = 0x15U,	/*!< The packet has valid time expired */
	satp_error_packet_expired = 0x16U,			/*!< The packet keep alive is invalid */
	satp_error_packet_unsequenced = 0x17U,		/*!< The packet was received out of sequence */
	satp_error_random_failure = 0x18U,			/*!< The random generator has failed */
	satp_error_receive_failure = 0x19U,			/*!< The receiver failed at the network layer */
	satp_error_transmit_failure = 0x1AU,		/*!< The transmitter failed at the network layer */
	satp_error_unknown_protocol = 0x1BU,		/*!< The protocol string was not recognized */
	satp_error_unsequenced = 0x1CU,				/*!< The packets sequence number is out of sync */
	satp_error_verify_failure = 0x1DU,			/*!< The expected data could not be verified */
	satp_error_general_failure = 0xFFU			/*!< A general failure occurred */
} satp_errors;

/*!
 * \enum satp_flags
 * \brief The SATP packet flag values.
 * This enumeration defines the flag values used in SATP packets to indicate the type and purpose of the packet.
 */
SATP_EXPORT_API typedef enum satp_flags
{
	satp_flag_none = 0x00U,						/*!< No flag was selected */
	satp_flag_connect_request = 0x01U,			/*!< The packet contains a connection request */
	satp_flag_connect_response = 0x02U,			/*!< The packet contains a connection response */
	satp_flag_connection_terminate = 0x03U,		/*!< Indicates that the connection is to be terminated */
	satp_flag_encrypted_message = 0x04U,		/*!< The packet contains an encrypted message */
	satp_flag_authentication_request = 0x05U,	/*!< The packet contains an authentication request */
	satp_flag_authentication_response = 0x06U,	/*!< The packet contains an authentication response */
	satp_flag_auth_verify = 0x08U,				/*!< The packet contains an authentication verify message */
	satp_flag_keepalive_request = 0x09U,		/*!< The packet is a keep alive request */
	satp_flag_session_established = 0x0AU,		/*!< Indicates that the session has been established */
	satp_flag_error_condition = 0xFFU,			/*!< Indicates that the connection experienced an error */
} satp_flags;

/*!
* \enum satp_messages
* \brief The logging message enumeration
*/
SATP_EXPORT_API typedef enum satp_messages
{
	satp_messages_none = 0x00U,						/*!< No configuration was specified */
	satp_messages_accept_fail = 0x01U,				/*!< The socket accept failed */
	satp_messages_listen_fail = 0x02U,				/*!< The listener socket could not connect */
	satp_messages_bind_fail = 0x03U,				/*!< The listener socket could not bind to the address */
	satp_messages_create_fail = 0x04U,				/*!< The listener socket could not be created */
	satp_messages_connect_success = 0x05U,			/*!< The server connected to a host */
	satp_messages_receive_fail = 0x06U,				/*!< The socket receive function failed */
	satp_messages_allocate_fail = 0x07U,			/*!< The server memory allocation request has failed */
	satp_messages_kex_fail = 0x08U,					/*!< The key exchange has experienced a failure */
	satp_messages_disconnect = 0x09U,				/*!< The server has disconnected the client */
	satp_messages_disconnect_fail = 0x0AU,			/*!< The server has disconnected the client due to an error */
	satp_messages_socket_message = 0x0BU,			/*!< The server has had a socket level error */
	satp_messages_queue_empty = 0x0CU,				/*!< The server has reached the maximum number of connections */
	satp_messages_listener_fail = 0x0DU,			/*!< The server listener socket has failed */
	satp_messages_sockalloc_fail = 0x0EU,			/*!< The server has run out of socket connections */
	satp_messages_decryption_fail = 0x0FU,			/*!< The message decryption has failed */
	satp_messages_keepalive_fail = 0x10U,			/*!< The keepalive function has failed */
	satp_messages_keepalive_timeout = 0x11U,		/*!< The keepalive period has been exceeded */
	satp_messages_connection_fail = 0x12U,			/*!< The connection failed or was interrupted */
	satp_messages_invalid_request = 0x13U,			/*!< The function received an invalid request */
	satp_messages_system_message = 0x14U,			/*!< The host encountered an error */
} satp_messages;

/*!
 * \struct satp_connection_state
 * \brief The SATP socket connection state structure
 */
SATP_EXPORT_API typedef struct satp_connection_state
{
	qsc_socket target;							/*!< The target socket structure */
	qsc_rcs_state rxcpr;						/*!< The receive channel cipher state */
	qsc_rcs_state txcpr;						/*!< The transmit channel cipher state */
	uint64_t rxseq;								/*!< The receive channels packet sequence number  */
	uint64_t txseq;								/*!< The transmit channels packet sequence number  */
	uint32_t cid;								/*!< The connections instance count */
	satp_flags exflag;							/*!< The KEX position flag */
	bool receiver;								/*!< The instance was initialized in listener mode */
} satp_connection_state;

/*!
 * \struct satp_device_key
 * \brief The SATP device key structure.
 * This structure represents the SATP device key, which is derived from the server key.
 * It includes the device key identity, device derivation key, and an expiration time.
 */
SATP_EXPORT_API typedef struct satp_device_key
{
	QSC_SIMD_ALIGN uint8_t ktree[SATP_DKEY_SIZE * SATP_KEY_TREE_COUNT];	/*!< The device key tree */
	QSC_SIMD_ALIGN uint8_t kid[SATP_KID_SIZE];	/*!< The device identity string */
	QSC_SIMD_ALIGN uint8_t stc[SATP_SKEY_SIZE]; /*!< The server's long term secret */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
	uint8_t* spass;								/*!< The pointer to the client passphrase hash */
} satp_device_key;

/*!
 * \struct satp_master_key
 * \brief The SATP master key structure.
 * This structure holds the SATP master key information, including the key identity, the master derivation key,
 * and the expiration time. The master key is used as the root from which branch keys are derived.
 */
SATP_EXPORT_API typedef struct satp_master_key
{
    QSC_SIMD_ALIGN uint8_t mdk[SATP_MKEY_SIZE];	/*!< The master derivation key */
    QSC_SIMD_ALIGN uint8_t mid[SATP_MID_SIZE];	/*!< Master key ID (domain identifier) */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} satp_master_key;

/*!
 * \struct satp_server_key
 * \brief The SATP server key structure.
 * This structure represents the SATP server key, which is derived from the master key. It contains the server's key identity,
 * server derivation key, and expiration time.
 */
SATP_EXPORT_API typedef struct satp_server_key
{
    QSC_SIMD_ALIGN uint8_t sdk[SATP_SKEY_SIZE]; /*!< The server derivation key */
    QSC_SIMD_ALIGN uint8_t sid[SATP_SID_SIZE];	/*!< Server key ID (domain+branch identifier) */
	QSC_SIMD_ALIGN uint8_t stc[SATP_SKEY_SIZE]; /*!< The server long term secret */
	uint64_t expiration;						/*!< The expiration time in seconds from epoch */
} satp_server_key;

/*!
 * \struct satp_keep_alive_state
 * \brief The SATP keep alive state structure.
 * This structure tracks the state of keep alive messages within SATP. It includes the epoch time when the last
 * keep alive message was sent, a packet sequence counter, and a flag indicating whether a response has been received.
 */
SATP_EXPORT_API typedef struct satp_keep_alive_state
{
	uint64_t etime;								/*!< The keep alive epoch time */
	uint64_t seqctr;							/*!< The keep alive packet sequence number */
	bool recd;									/*!< Indicates whether a keep alive response was received */
} satp_keep_alive_state;

/*!
 * \struct satp_network_packet
 * \brief The SATP network packet structure.
 * This structure defines the format of a SATP network packet. It includes a packet flag, the message length,
 * a sequence number, a UTC timestamp for packet creation, and a pointer to the message data.
 */
SATP_EXPORT_API typedef struct satp_network_packet
{
	uint8_t flag;								/*!< The packet flag */
	uint32_t msglen;							/*!< The message length in bytes */
	uint64_t sequence;							/*!< The packet sequence number */
	uint64_t utctime;							/*!< The packet creation time in UTC seconds from epoch */
	uint8_t* pmessage;							/*!< A pointer to the packet's message data */
} satp_network_packet;

/*!
* \brief Close the network connection between hosts
*
* \param cns: A pointer to the connection state structure
* \param err: The error message
* \param notify: Notify the remote host connection is closing
*/
SATP_EXPORT_API void satp_connection_close(satp_connection_state* cns, satp_errors err, bool notify);

/*!
* \brief Reset the connection state
*
* \param cns: A pointer to the connection state structure
*/
SATP_EXPORT_API void satp_connection_dispose(satp_connection_state* cns);

/*!
 * \brief Decrypt an error message.
 *
 * \param cns A pointer to the SATP client state structure.
 * \param message [const] The serialized error packet.
 * \param merr A pointer to an \c satp_errors error value.
 *
 * \return Returns true if the message was decrypted successfully, false on failure.
 */
SATP_EXPORT_API bool satp_decrypt_error_message(satp_errors* merr, satp_connection_state* cns, const uint8_t* message);

/*!
 * \brief Decrypt an SATP packet.
 *
 * This function decrypts the message contained in the input SATP network packet using the client's current
 * decryption state, and copies the plaintext into the provided output buffer. The length of the decrypted
 * message is returned via the msglen parameter.
 *
 * \param cns A pointer to the SATP client state structure.
 * \param packetin [const] A pointer to the input SATP network packet.
 * \param message The output buffer where the decrypted message will be stored.
 * \param msglen A pointer to a variable that receives the length of the decrypted message.
 *
 * \return Returns a value of type \c satp_errors indicating the result of the decryption operation.
 */
SATP_EXPORT_API satp_errors satp_decrypt_packet(satp_connection_state* cns, const satp_network_packet* packetin, uint8_t* message, size_t* msglen);

/*!
 * \brief Encrypt a message into an SATP packet.
 *
 * This function encrypts the provided plaintext message using the client's current transmit cipher state.
 * It then constructs an SATP network packet containing the encrypted message along with the appropriate
 * header fields (such as message length, sequence number, and UTC timestamp), and outputs the packet via the
 * provided structure.
 *
 * \param cns A pointer to the SATP client state structure.
 * \param message [const] The plaintext message to be encrypted.
 * \param msglen The length of the plaintext message in bytes.
 * \param packetout A pointer to the output SATP network packet structure.
 *
 * \return Returns a value of type \c satp_errors indicating the success or failure of the encryption process.
 */
SATP_EXPORT_API satp_errors satp_encrypt_packet(satp_connection_state* cns, const uint8_t* message, size_t msglen, satp_network_packet* packetout);

/**
 * \brief Deserialize a client device key.
 * This function deserializes a byte array into a SATP device key structure.
 *
 * \param dkey The output SATP device key structure.
 * \param input The input serialized device key array of size \c SATP_DEVKEY_ENCODED_SIZE.
 */
SATP_EXPORT_API void satp_deserialize_device_key(satp_device_key* dkey, const uint8_t* input);

/**
 * \brief Serialize a client device key.
 * This function serializes a SATP device key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized device key.
 * \param dkey The input SATP device key structure.
 */
SATP_EXPORT_API void satp_serialize_device_key(uint8_t* output, const satp_device_key* dkey);

/**
 * \brief Return a string description of an SATP error code.
 * This function returns a human-readable string corresponding to the provided SATP error code.
 *
 * \param error The SATP error code.
 *
 * \return Returns a pointer to the error description string, or NULL if the error code is not recognized.
 */
SATP_EXPORT_API const char* satp_error_to_string(satp_errors error);

/**
 * \brief Extract a device key.
 * This function extracts a device key by hashing the server key and key identity.
 *
 * \param dk The pointer to the output device key array.
 * \param sk The input server derivation key.
 * \param kid The key identity including client id and key counter.
 */
SATP_EXPORT_API bool satp_extract_device_key(uint8_t* dk, const uint8_t* sk, const uint8_t* kid);

/*!
* \brief Get the error string description
*
* \param emsg: The message enumeration
*
* \return Returns a pointer to the message string or NULL
*/
SATP_EXPORT_API const char* satp_get_error_description(satp_messages emsg);

/*!
* \brief Log the message, socket error, and string description
*
* \param emsg: The message enumeration
* \param err: The socket exception enumeration
* \param msg: [const] The message string
*/
SATP_EXPORT_API void satp_log_error(satp_messages emsg, qsc_socket_exceptions err, const char* msg);

/*!
* \brief Log a system error message
*
* \param err: The system error enumerator
*/
SATP_EXPORT_API void satp_log_system_error(satp_errors err);

/*!
* \brief Log a message
*
* \param emsg: The message enumeration
*/
SATP_EXPORT_API void satp_log_message(satp_messages emsg);

/*!
* \brief Log a message and description
*
* \param emsg: The message enumeration
* \param msg: [const] The message string
*/
SATP_EXPORT_API void satp_log_write(satp_messages emsg, const char* msg);

/*!
* \brief Populate a packet structure with an error message
*
* \param packet: A pointer to the packet structure
* \param error: The error type
*/
SATP_EXPORT_API void satp_packet_error_message(satp_network_packet* packet, satp_errors error);

/**
 * \brief Deserialize a master key from a byte array.
 * This function deserializes a byte array into a SATP master key structure.
 *
 * \param mkey The output SATP master key structure.
 * \param input The input serialized master key array of size \c SATP_MSTKEY_ENCODED_SIZE.
 */
SATP_EXPORT_API void satp_deserialize_master_key(satp_master_key* mkey, const uint8_t* input);

/**
 * \brief Serialize a master key into a byte array.
 * This function serializes a SATP master key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized master key.
 * \param mkey The input SATP master key structure.
 */
SATP_EXPORT_API void satp_serialize_master_key(uint8_t* output, const satp_master_key* mkey);

/**
 * \brief Deserialize a server key from a byte array.
 * This function deserializes a byte array into a SATP server key structure.
 *
 * \param skey The output SATP server key structure.
 * \param input The input serialized server key array of size \c SATP_SRVKEY_ENCODED_SIZE.
 */
SATP_EXPORT_API void satp_deserialize_server_key(satp_server_key* skey, const uint8_t* input);

/**
 * \brief Serialize a server key into a byte array.
 * This function serializes a SATP server key structure into a byte array.
 *
 * \param output The output byte array to hold the serialized server key.
 * \param skey The input SATP server key structure.
 */
SATP_EXPORT_API void satp_serialize_server_key(uint8_t* output, const satp_server_key* skey);

/**
 * \brief Increment the serialized key
 * This function clears a key at the current position and increments the kid counter.
 *
 * \param sdkey The input/output serialized SATP server key structure.
 */
SATP_EXPORT_API void satp_increment_device_key(uint8_t* sdkey);

/**
 * \brief Generate a master key-set.
 * This function generates a new SATP master key-set. It populates the provided master key structure with a randomly
 * generated master derivation key and the key identity, and sets the expiration time. The master key serves as the root
 * from which branch keys are derived.
 *
 * \param mkey A pointer to the SATP master key structure.
 * \param mid [const] The master key identity.
 *
 * \return Returns false if the random generator fails; otherwise, returns true.
 */
SATP_EXPORT_API bool satp_generate_master_key(satp_master_key* mkey, const uint8_t* mid);

/**
 * \brief Generate a server key-set.
 * This function generates a new SATP server key-set based on the provided master key. It populates the server key structure
 * with a derived server key and sets the key identity and expiration time.
 *
 * \param skey A pointer to the SATP server key structure.
 * \param mkey [const] A pointer to the SATP master key structure.
 * \param sid [const] The key identity string.
 *
 * \return Returns false if the random generator fails; otherwise, returns true.
 */
SATP_EXPORT_API bool satp_generate_server_key(satp_server_key* skey, const satp_master_key* mkey, const uint8_t* sid);

/**
 * \brief Generate a device key-set.
 * This function generates a new SATP device key-set using the provided server key. It derives the device key from the server
 * key and sets the key identity and expiration time.
 *
 * \param dkey A pointer to the SATP device key structure.
 * \param skey [const] A pointer to the SATP server key structure.
 * \param did [const] The key identity string.
 */
SATP_EXPORT_API void satp_generate_device_key(satp_device_key* dkey, const satp_server_key* skey, const uint8_t* did);

/**
 * \brief Clear a SATP network packet.
 * This function resets the fields of a SATP network packet to zero, effectively clearing its state.
 *
 * \param packet A pointer to the SATP network packet to clear.
 */
SATP_EXPORT_API void satp_packet_clear(satp_network_packet* packet);

/*!
* \brief Populate a packet header and set the creation time
*
* \param packetout: A pointer to the output packet structure
* \param flag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*/
SATP_EXPORT_API void satp_packet_header_create(satp_network_packet* packetout, satp_flags flag, uint64_t sequence, uint32_t msglen);

/**
 * \brief Deserialize a byte array into a SATP packet header.
 * This function converts a serialized byte array representing a SATP packet header into a structured SATP network packet.
 *
 * \param header A pointer to the input header byte array.
 * \param packet A pointer to the SATP network packet structure to populate.
 */
SATP_EXPORT_API void satp_packet_header_deserialize(const uint8_t* header, satp_network_packet* packet);

/**
 * \brief Serialize a SATP packet header into a byte array.
 * This function converts a structured SATP network packet header into a serialized byte array for transmission.
 *
 * \param packet A pointer to the SATP network packet structure to serialize.
 * \param header The output header byte array.
 */
SATP_EXPORT_API void satp_packet_header_serialize(const satp_network_packet* packet, uint8_t* header);

/*!
* \brief Validate a packet header and timestamp
*
* \param packetin: A pointer to the input packet structure
* \param pktflag: The packet flag
* \param sequence: The packet sequence number
* \param msglen: The length of the message array
*
* \return: Returns the function error state
*/
SATP_EXPORT_API satp_errors satp_packet_header_validate(const satp_network_packet* packetin, satp_flags pktflag, uint64_t sequence, uint32_t msglen);

/**
 * \brief Set the local UTC seconds time in a SATP packet header.
 * This function updates the SATP packet header with the current UTC time (in seconds).
 *
 * \param packet A pointer to the SATP network packet structure.
 */
SATP_EXPORT_API void satp_packet_set_utc_time(satp_network_packet* packet);

/**
 * \brief Check if a SATP packet is received within the valid time threshold.
 * This function compares the UTC time in the SATP packet header against the local time to verify that the packet
 * was received within the allowed time threshold.
 *
 * \param packet A pointer to the SATP network packet structure.
 *
 * \return Returns true if the packet was received within the valid time threshold; otherwise, returns false.
 */
SATP_EXPORT_API bool satp_packet_time_valid(const satp_network_packet* packet);

/**
 * \brief Serialize a SATP packet into a byte array.
 * This function converts a SATP network packet into a contiguous byte stream suitable for network transmission.
 *
 * \param packet A pointer to the SATP network packet structure.
 * \param pstream The output byte stream buffer.
 *
 * \return Returns the size (in bytes) of the serialized packet.
 */
SATP_EXPORT_API size_t satp_packet_to_stream(const satp_network_packet* packet, uint8_t* pstream);

/**
 * \brief Send a plaintext SATP network error message 
 * Used only during key exchange, the connection close is sent over an encrypted tunnel
 *
 * \param sock A pointer to the SATP network packet structure.
 * \param error The output byte stream buffer.
 */
SATP_EXPORT_API void satp_send_network_error(const qsc_socket* sock, satp_errors error);

/**
 * \brief Deserialize a byte stream into a SATP network packet.
 * This function converts a contiguous byte stream into a structured SATP network packet.
 *
 * \param pstream A pointer to the input byte stream.
 * \param packet A pointer to the SATP network packet structure to populate.
 */
SATP_EXPORT_API void satp_stream_to_packet(const uint8_t* pstream, satp_network_packet* packet);

#endif
