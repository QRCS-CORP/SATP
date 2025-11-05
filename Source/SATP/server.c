#include "server.h"
#include "connections.h"
#include "kex.h"
#include "acp.h"
#include "async.h"
#include "encoding.h"
#include "intutils.h"
#include "memutils.h"
#include "scb.h"
#include "sha3.h"
#include "stringutils.h"
#include "timestamp.h"

#define SERVER_AUTHENTICATION_REQUEST_MESSAGE_SIZE (SATP_DID_SIZE + SATP_HASH_SIZE + SATP_MACTAG_SIZE)
#define SERVER_AUTHENTICATION_REQUEST_PACKET_SIZE (SATP_HEADER_SIZE + SERVER_AUTHENTICATION_REQUEST_MESSAGE_SIZE)
#define SERVER_AUTHENTICATION_RESPONSE_MESSAGE_SIZE (SATP_SID_SIZE + SATP_MACTAG_SIZE)
#define SERVER_AUTHENTICATION_RESPONSE_PACKET_SIZE (SATP_HEADER_SIZE + SERVER_AUTHENTICATION_RESPONSE_MESSAGE_SIZE)

/** \cond */
typedef struct server_receiver_state
{
	uint8_t sid[SATP_SID_SIZE];
	satp_connection_state* pcns;
	const satp_server_key* skey;
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t);
	void (*disconnect_callback)(satp_connection_state*);
	bool (*authentication_callback)(satp_connection_state*, const uint8_t*, size_t);
} server_receiver_state;
/** \endcond */

/** \cond */
static bool m_server_pause;
static bool m_server_run;

static void server_poll_sockets()
{
	size_t clen;
	qsc_mutex mtx;

	clen = satp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		const satp_connection_state* cns = satp_connections_index(i);

		if (cns != NULL && satp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == false)
			{
				satp_connections_reset(cns->cid);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

static void server_state_initialize(satp_kex_server_state* pkss, server_receiver_state* prcv)
{
	/* copy the server key */
	qsc_memutils_copy(pkss->sdk, prcv->skey->sdk, SATP_SKEY_SIZE);
	qsc_memutils_copy(pkss->sid, prcv->skey->sid, SATP_SID_SIZE);
	qsc_memutils_copy(pkss->stc, prcv->skey->stc, SATP_SKEY_SIZE);
	pkss->expiration = prcv->skey->expiration;
	/* hook up the callback and reset the server key pointer */
	prcv->skey = NULL;
}

static bool server_authentication_response(server_receiver_state* prcv)
{
	satp_network_packet pkt = { 0U };
	uint8_t sbuf[SERVER_AUTHENTICATION_RESPONSE_PACKET_SIZE] = { 0U };
	char msgstr[SERVER_AUTHENTICATION_RESPONSE_PACKET_SIZE] = { 0U };
	size_t mlen;

	mlen = 0;

	/* encrypt the packet */
	pkt.pmessage = sbuf + SATP_HEADER_SIZE;
	satp_encrypt_packet(prcv->pcns, prcv->sid, SATP_SID_SIZE, &pkt);

	/* serialize and send to the client */
	mlen = satp_packet_to_stream(&pkt, msgstr);
	qsc_socket_send(&prcv->pcns->target, msgstr, mlen, qsc_socket_send_flag_none);

	return (mlen == SERVER_AUTHENTICATION_RESPONSE_PACKET_SIZE);
}

static satp_errors server_receive_loop(void* prcv)
{
	assert(prcv != NULL);

	satp_network_packet pkt = { 0U };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0U };
	server_receiver_state* pprcv;
	satp_kex_server_state* pkss;
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	satp_errors err;
	bool auth;

	auth = false;
	pprcv = (server_receiver_state*)prcv;
	qsc_memutils_copy(cadd, (const char*)pprcv->pcns->target.address, sizeof(cadd));
	pkss = (satp_kex_server_state*)qsc_memutils_malloc(sizeof(satp_kex_server_state));

	if (pkss != NULL)
	{
		/* initialze the key state and run the key exchange */
		server_state_initialize(pkss, prcv);
		err = satp_kex_server_key_exchange(pkss, pprcv->pcns);

		/* release the kex state */
		qsc_memutils_alloc_free(pkss);
		pkss = NULL;

		if (err == satp_error_none)
		{
			rbuf = (uint8_t*)qsc_memutils_malloc(SATP_HEADER_SIZE);

			if (rbuf != NULL)
			{
				while (pprcv->pcns->target.connection_status == qsc_socket_state_connected)
				{
					mlen = 0U;
					slen = 0U;

					plen = qsc_socket_peek(&pprcv->pcns->target, rbuf, SATP_HEADER_SIZE);

					if (plen == SATP_HEADER_SIZE)
					{
						satp_packet_header_deserialize(rbuf, &pkt);

						if (pkt.msglen > 0U && pkt.msglen <= SATP_MESSAGE_MAX)
						{
							plen = pkt.msglen + SATP_HEADER_SIZE;
							rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);
						}

						if (rbuf != NULL)
						{
							qsc_memutils_clear(rbuf, plen);
							mlen = qsc_socket_receive(&pprcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

							if (mlen != 0U)
							{
								pkt.pmessage = rbuf + SATP_HEADER_SIZE;

								if (pkt.flag == satp_flag_encrypted_message)
								{
									uint8_t* mstr;

									slen = pkt.msglen + SATP_MACTAG_SIZE;
									mstr = (uint8_t*)qsc_memutils_malloc(slen);

									if (mstr != NULL)
									{
										qsc_memutils_clear(mstr, slen);

										err = satp_decrypt_packet(pprcv->pcns, &pkt, mstr, &mlen);

										if (err == satp_error_none)
										{
											if (auth)
											{
												pprcv->receive_callback(pprcv->pcns, (char*)mstr, mlen);
											}
											else
											{
												if (pprcv->authentication_callback(pprcv->pcns, (char*)mstr, mlen) == true)
												{
													/* authentication challenge succeeded, the client is authenticated */
													if (server_authentication_response(pprcv) == true)
													{
														auth = true;
													}
													else
													{
														/* response send failed, set the error and disconnect */
														err = satp_error_authentication_failure;
														break;
													}
												}
												else
												{
													/* callback authentication failed, set the error and disconnect */
													err = satp_error_authentication_failure;
													break;
												}
											}
										}
										else
										{
											/* close the connection on authentication failure */
											err = satp_error_decryption_failure;
											break;
										}

										qsc_memutils_alloc_free(mstr);
									}
									else
									{
										/* close the connection on memory allocation failure */
										err = satp_error_allocation_failure;
										break;
									}
								}
								else if (pkt.flag == satp_flag_error_condition)
								{
									err = satp_decrypt_error_message(pprcv->pcns, rbuf);
									break;
								}
								else
								{
									/* unknown message type, we fail out of caution but could ignore */
									err = satp_error_receive_failure;
									break;
								}
							}
							else
							{
								qsc_socket_exceptions serr = qsc_socket_get_last_error();

								if (serr != qsc_socket_exception_success)
								{
									/* fatal socket errors */
									if (serr == qsc_socket_exception_circuit_reset ||
										serr == qsc_socket_exception_circuit_terminated ||
										serr == qsc_socket_exception_circuit_timeout ||
										serr == qsc_socket_exception_dropped_connection ||
										serr == qsc_socket_exception_network_failure ||
										serr == qsc_socket_exception_shut_down)
									{
										err = satp_error_connection_failure;
										break;
									}
									else
									{
										err = satp_error_receive_failure;
									}
								}
							}
						}
						else
						{
							/* close the connection on memory allocation failure */
							err = satp_error_allocation_failure;
							break;
						}
					}
				}

				qsc_memutils_alloc_free(rbuf);
			}
			else
			{
				/* close the connection on memory allocation failure */
				err = satp_error_allocation_failure;
			}

			if (pprcv->disconnect_callback != NULL)
			{
				pprcv->disconnect_callback(pprcv->pcns);
			}
		}
		else
		{
			err = satp_error_kex_auth_failure;
		}

		if (pprcv != NULL)
		{
			satp_connections_reset(pprcv->pcns->cid);
			qsc_memutils_alloc_free(pprcv);
			pprcv = NULL;
		}
	}
	else
	{
		err = satp_error_allocation_failure;
	}

	return err;
}

static satp_errors server_start(const satp_server_key* skey,
	const qsc_socket* source,
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(satp_connection_state*),
	bool (*authentication_callback)(satp_connection_state*, const uint8_t*, size_t))
{
	assert(skey != NULL);
	assert(source != NULL);
	assert(receive_callback != NULL);

	qsc_socket_exceptions res;
	satp_errors err;

	err = satp_error_none;
	m_server_pause = false;
	m_server_run = true;
	satp_connections_initialize(SATP_CONNECTIONS_INIT, SATP_CONNECTIONS_MAX);

	do
	{
		satp_connection_state* cns = satp_connections_next();

		if (cns != NULL)
		{
			res = qsc_socket_accept(source, &cns->target);

			if (res == qsc_socket_exception_success)
			{
				server_receiver_state* prcv = (server_receiver_state*)qsc_memutils_malloc(sizeof(server_receiver_state));

				if (prcv != NULL)
				{
					cns->target.connection_status = qsc_socket_state_connected;
					prcv->pcns = cns;
					prcv->disconnect_callback = disconnect_callback;
					prcv->receive_callback = receive_callback;
					prcv->authentication_callback = authentication_callback;
					qsc_memutils_copy(prcv->sid, skey->sid, SATP_SID_SIZE);
					prcv->skey = skey;

					qsc_async_thread_create(&server_receive_loop, prcv);
					server_poll_sockets();
				}
				else
				{
					satp_connections_reset(cns->cid);
					err = satp_error_allocation_failure;
				}
			}
			else
			{
				satp_connections_reset(cns->cid);
				err = satp_error_accept_fail;
			}
		}
		else
		{
			err = satp_error_hosts_exceeded;
		}

		while (m_server_pause == true)
		{
			qsc_async_thread_sleep(SATP_SERVER_PAUSE_INTERVAL);
		}
	} while (m_server_run == true);

	return err;
}
/** \endcond */

/* Public Functions */

void satp_server_broadcast(const uint8_t* message, size_t msglen)
{
	size_t clen;
	size_t mlen;
	qsc_mutex mtx;
	satp_network_packet pkt = { 0U };
	uint8_t msgstr[SATP_CONNECTION_MTU] = { 0U };

	clen = satp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		satp_connection_state* cns = satp_connections_index(i);

		if (cns != NULL && satp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				satp_encrypt_packet(cns, message, msglen, &pkt);
				mlen = satp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}

			qsc_async_mutex_unlock_ex(mtx);
		}
	}
}

void satp_server_passphrase_generate(char* passphrase, size_t length)
{
	char trnd[128U] = { 0U };
	size_t clen;

	clen = 0;

	while (clen < length)
	{
		qsc_acp_generate((uint8_t*)trnd, sizeof(trnd));

		for (size_t i = 0; i < sizeof(trnd); ++i)
		{
			if (trnd[i] > 32U && trnd[i] < 127U)
			{
				passphrase[clen] = trnd[i];
				++clen;

				if (clen >= length - 1)
				{
					break;
				}
			}
		}

		qsc_memutils_clear(trnd, sizeof(trnd));
	}
}

void satp_server_passphrase_hash_generate(uint8_t* phash, char* passphrase, size_t passlen)
{
	qsc_scb_state sscb = { 0U };

	qsc_scb_initialize(&sscb, passphrase, passlen, NULL, 0, 1U, 1U);
	qsc_scb_generate(&sscb, phash, SATP_HASH_SIZE);
	qsc_scb_dispose(&sscb);
}

bool satp_server_passphrase_hash_verify(const uint8_t* phash, char* passphrase, size_t passlen)
{
	uint8_t tmph[SATP_HASH_SIZE] = { 0U };

	satp_server_passphrase_hash_generate(tmph, passphrase, passlen);

	return (qsc_intutils_verify(tmph, phash, SATP_HASH_SIZE) == 0U);
}

void satp_server_pause()
{
	m_server_pause = true;
}

void satp_server_quit()
{
	size_t clen;
	qsc_mutex mtx;

	clen = satp_connections_size();

	for (size_t i = 0U; i < clen; ++i)
	{
		satp_connection_state* cns = satp_connections_index(i);

		if (cns != NULL && satp_connections_active(i) == true)
		{
			mtx = qsc_async_mutex_lock_ex();

			if (qsc_socket_is_connected(&cns->target) == true)
			{
				qsc_socket_close_socket(&cns->target);
			}

			satp_connections_reset(cns->cid);

			qsc_async_mutex_unlock_ex(mtx);
		}
	}

	satp_connections_dispose();
	m_server_run = false;
}

void satp_server_resume()
{
	m_server_pause = false;
}

satp_errors satp_server_start_ipv4(const satp_server_key* skey,
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(satp_connection_state*),
	bool (*authentication_callback)(satp_connection_state*, const uint8_t*, size_t))
{
	assert(skey != NULL);
	assert(receive_callback != NULL);

	qsc_socket ssck = { 0U };
	qsc_ipinfo_ipv4_address addt = { 0U };
	qsc_socket_exceptions res;
	satp_errors err;

	addt = qsc_ipinfo_ipv4_address_any();
	qsc_socket_server_initialize(&ssck);
	res = qsc_socket_create(&ssck, qsc_socket_address_family_ipv4, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv4(&ssck, &addt, SATP_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(&ssck, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				err = server_start(skey, &ssck, receive_callback, disconnect_callback, authentication_callback);
			}
			else
			{
				err = satp_error_listener_fail;
			}
		}
		else
		{
			err = satp_error_connection_failure;
		}
	}
	else
	{
		err = satp_error_connection_failure;
	}

	return err;
}

satp_errors satp_server_start_ipv6(const satp_server_key* skey,
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t),
	void (*disconnect_callback)(satp_connection_state*),
	bool (*authentication_callback)(satp_connection_state*, const uint8_t*, size_t))
{
	assert(skey != NULL);
	assert(receive_callback != NULL);

	qsc_socket ssck = { 0U };
	qsc_ipinfo_ipv6_address addt = { 0U };
	qsc_socket_exceptions res;
	satp_errors err;

	addt = qsc_ipinfo_ipv6_address_any();
	qsc_socket_server_initialize(&ssck);
	res = qsc_socket_create(&ssck, qsc_socket_address_family_ipv6, qsc_socket_transport_stream, qsc_socket_protocol_tcp);

	if (res == qsc_socket_exception_success)
	{
		res = qsc_socket_bind_ipv6(&ssck, &addt, SATP_SERVER_PORT);

		if (res == qsc_socket_exception_success)
		{
			res = qsc_socket_listen(&ssck, QSC_SOCKET_SERVER_LISTEN_BACKLOG);

			if (res == qsc_socket_exception_success)
			{
				err = server_start(skey, &ssck, receive_callback, disconnect_callback, authentication_callback);
			}
			else
			{
				err = satp_error_listener_fail;
			}
		}
		else
		{
			err = satp_error_connection_failure;
		}
	}
	else
	{
		err = satp_error_connection_failure;
	}

	return err;
}
