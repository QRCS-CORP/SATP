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
