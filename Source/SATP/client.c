#include "client.h"
#include "kex.h"
#include "acp.h"
#include "async.h"
#include "intutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socket.h"
#include "socketclient.h"

#define CLIENT_AUTHENTICATION_REQUEST_MESSAGE_SIZE (SATP_DID_SIZE + SATP_HASH_SIZE + SATP_MACTAG_SIZE)
#define CLIENT_AUTHENTICATION_REQUEST_PACKET_SIZE (SATP_HEADER_SIZE + CLIENT_AUTHENTICATION_REQUEST_MESSAGE_SIZE)
#define CLIENT_AUTHENTICATION_RESPONSE_MESSAGE_SIZE (SATP_SID_SIZE + SATP_MACTAG_SIZE)
#define CLIENT_AUTHENTICATION_RESPONSE_PACKET_SIZE (SATP_HEADER_SIZE + CLIENT_AUTHENTICATION_RESPONSE_MESSAGE_SIZE)

typedef struct client_receiver_state
{
	satp_connection_state* pcns;
	void (*callback)(satp_connection_state*, const uint8_t*, size_t);
} client_receiver_state;

static void client_connection_dispose(client_receiver_state* prcv)
{
	/* send a close notification to the server */
	if (qsc_socket_is_connected(&prcv->pcns->target) == true)
	{
		satp_connection_close(prcv->pcns, satp_error_none, true);
	}

	/* dispose of resources */
	satp_connection_dispose(prcv->pcns);
}

static bool client_initialize(satp_kex_client_state* cls, satp_connection_state* cns, satp_device_key* ckey)
{
	SATP_ASSERT(cls != NULL);
	SATP_ASSERT(ckey != NULL);

	const uint8_t* pkey;
	bool res;

	res = false;

	if (cls != NULL && ckey != NULL)
	{
		/* get the current key index and key pointer */
		cls->kidx = qsc_intutils_be8to32(ckey->kid + SATP_DID_SIZE);

		if (cls->kidx < SATP_KEY_TREE_COUNT)
		{
			pkey = ckey->ktree + (cls->kidx * SATP_DKEY_SIZE);

			/* Important: check if key is zeroed */
			res = qsc_memutils_zeroed(pkey, SATP_DKEY_SIZE);

			if (res == false)
			{
				/* copy the current key from the set */
				qsc_memutils_copy(cls->dk, pkey, SATP_DKEY_SIZE);
				/* copy kid and server secret */
				qsc_memutils_copy(cls->kid, ckey->kid, SATP_KID_SIZE);
				qsc_memutils_copy(cls->stc, ckey->stc, SATP_SKEY_SIZE);
				qsc_memutils_clear(cls->hc, SATP_HASH_SIZE);

				cls->expiration = ckey->expiration;
				cns->rxseq = 0U;
				cns->txseq = 0U;
				cns->exflag = satp_flag_none;
				res = true;
			}
		}
	}

	return res;
}

static satp_errors client_receive_loop(client_receiver_state* prcv)
{
	assert(prcv != NULL);

	satp_network_packet pkt = { 0U };
	char cadd[QSC_SOCKET_ADDRESS_MAX_SIZE] = { 0U };
	uint8_t* rbuf;
	size_t mlen;
	size_t plen;
	size_t slen;
	satp_errors err;

	err = satp_error_general_failure;
	qsc_memutils_copy(cadd, (const char*)prcv->pcns->target.address, sizeof(cadd));

	rbuf = (uint8_t*)qsc_memutils_malloc(SATP_HEADER_SIZE);

	if (rbuf != NULL)
	{
		while (prcv->pcns->target.connection_status == qsc_socket_state_connected)
		{
			mlen = 0U;
			slen = 0U;
			qsc_memutils_clear(rbuf, SATP_HEADER_SIZE);

			plen = qsc_socket_peek(&prcv->pcns->target, rbuf, SATP_HEADER_SIZE);

			if (plen == SATP_HEADER_SIZE)
			{
				satp_packet_header_deserialize(rbuf, &pkt);

				if (pkt.msglen > 0U && pkt.msglen <= SATP_MESSAGE_MAX)
				{
					plen = pkt.msglen + SATP_HEADER_SIZE;
					rbuf = (uint8_t*)qsc_memutils_realloc(rbuf, plen);

					if (rbuf != NULL)
					{
						qsc_memutils_clear(rbuf, plen);
						mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, plen, qsc_socket_receive_flag_wait_all);

						if (mlen > 0U)
						{
							pkt.pmessage = rbuf + SATP_HEADER_SIZE;

							if (pkt.flag == satp_flag_encrypted_message)
							{
								uint8_t* rmsg;

								slen = pkt.msglen;
								slen -= SATP_MACTAG_SIZE;
								rmsg = (uint8_t*)qsc_memutils_malloc(slen);

								if (rmsg != NULL)
								{
									qsc_memutils_clear(rmsg, slen);
									err = satp_decrypt_packet(prcv->pcns, &pkt, rmsg, &mlen);

									if (err == satp_error_none)
									{
										prcv->callback(prcv->pcns, rmsg, mlen);
									}
									else
									{
										/* close the connection on authentication failure */
										err = satp_error_decryption_failure;
										break;
									}

									qsc_memutils_alloc_free(rmsg);
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
								err = satp_decrypt_error_message(prcv->pcns, rbuf);
								break;
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
							err = satp_error_receive_failure;
							break;
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
			else
			{
				err = satp_error_receive_failure;
				break;
			}
		}

		qsc_memutils_alloc_free(rbuf);
	}
	else
	{
		err = satp_error_allocation_failure;
	}

	return err;
}

static bool client_authentication_request(const client_receiver_state* prcv, const satp_device_key* ckey)
{
	satp_network_packet pkt = { 0U };
	uint8_t pmsg[SATP_DID_SIZE + SATP_HASH_SIZE] = { 0U };
	uint8_t rbuf[CLIENT_AUTHENTICATION_RESPONSE_PACKET_SIZE] = { 0U };
	uint8_t sbuf[CLIENT_AUTHENTICATION_REQUEST_PACKET_SIZE] = { 0U };
	size_t mlen;
	bool res;

	res = false;

	/* copy the did and username/passphrase hash to the message */
	qsc_memutils_copy(pmsg, ckey->kid, SATP_DID_SIZE);
	qsc_memutils_copy(pmsg + SATP_DID_SIZE, ckey->spass, SATP_HASH_SIZE);

	/* encrypt the auth request */
	pkt.pmessage = sbuf + SATP_HEADER_SIZE;
	satp_encrypt_packet(prcv->pcns, pmsg, sizeof(pmsg), &pkt);

	/* send to the server */
	satp_packet_header_serialize(&pkt, sbuf);
	qsc_socket_send(&prcv->pcns->target, sbuf, CLIENT_AUTHENTICATION_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);

	/* wait for the server response */
	mlen = qsc_socket_receive(&prcv->pcns->target, rbuf, sizeof(rbuf), qsc_socket_receive_flag_wait_all);

	if (mlen == CLIENT_AUTHENTICATION_RESPONSE_PACKET_SIZE)
	{
		uint8_t tbuf[CLIENT_AUTHENTICATION_RESPONSE_PACKET_SIZE] = { 0U };

		/* decrypt the packet */
		mlen = SATP_SID_SIZE;
		satp_packet_header_deserialize(rbuf, &pkt);
		pkt.pmessage = rbuf + SATP_HEADER_SIZE;
		res = (satp_decrypt_packet(prcv->pcns, &pkt, tbuf, &mlen) == satp_error_none);

		if (res == true)
		{
			/* a return of the server id indicates success */
			res = (qsc_intutils_verify(ckey->kid, tbuf, SATP_SID_SIZE) == 0U);
		}
	}
	
	return res;
}

void satp_client_send_error(const qsc_socket* sock, satp_errors error)
{
	SATP_ASSERT(sock != NULL);

	if (sock != NULL)
	{
		if (qsc_socket_is_connected(sock) == true)
		{
			satp_network_packet resp = { 0U };
			uint8_t spct[SATP_HEADER_SIZE + SATP_ERROR_SIZE] = { 0U };

			resp.flag = satp_error_general_failure;
			resp.msglen = sizeof(uint8_t);
			resp.sequence = SATP_SEQUENCE_TERMINATOR;
			satp_packet_header_serialize(&resp, spct);
			spct[SATP_HEADER_SIZE] = (uint8_t)error;
			qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
		}
	}
}

satp_errors satp_client_connect_ipv4(satp_device_key* ckey,
	const qsc_ipinfo_ipv4_address* address, uint16_t port,
	void (*send_func)(satp_connection_state*),
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t))
{
	assert(ckey != NULL);
	assert(address != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	satp_kex_client_state* pcls;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	satp_errors err;

	pcls = NULL;
	prcv = NULL;

	if (ckey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));
		pcls = (satp_kex_client_state*)qsc_memutils_malloc(sizeof(satp_kex_client_state));

		if (prcv != NULL && pcls != NULL)
		{
			qsc_memutils_clear(prcv, sizeof(client_receiver_state));
			qsc_memutils_clear(pcls, sizeof(satp_kex_client_state));

			prcv->pcns = (satp_connection_state*)qsc_memutils_malloc(sizeof(satp_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_socket_client_initialize(&prcv->pcns->target);

				serr = qsc_socket_client_connect_ipv4(&prcv->pcns->target, address, port);

				if (serr == qsc_socket_exception_success)
				{
					/* initialize the client */
					err = satp_error_none;

					if (client_initialize(pcls, prcv->pcns, ckey) == true)
					{
						/* perform the key exchange */
						err = satp_kex_client_key_exchange(pcls, prcv->pcns);

						if (err == satp_error_none)
						{
							/* send the authentication request */
							if (client_authentication_request(prcv, ckey) == true)
							{
								/* start the receive loop on a new thread */
								qsc_async_thread_create((void*)&client_receive_loop, prcv);

								/* start the send loop on the main thread */
								send_func(prcv->pcns);
							}

							/* disconnect the socket */
							client_connection_dispose(prcv);
						}
					}
					else
					{
						err = satp_error_invalid_input;
					}
				}
				else
				{
					err = satp_error_connection_failure;
				}
			}
			else
			{
				err = satp_error_allocation_failure;
			}
		}
		else
		{
			err = satp_error_allocation_failure;
		}
	}
	else
	{
		err = satp_error_invalid_input;
	}

	if (pcls != NULL)
	{
		qsc_memutils_clear(pcls, sizeof(satp_kex_client_state));
		qsc_memutils_alloc_free(pcls);
		pcls = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_clear(prcv->pcns, sizeof(satp_connection_state));
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return err;
}

satp_errors satp_client_connect_ipv6(satp_device_key* ckey,
	const qsc_ipinfo_ipv6_address* address, uint16_t port,
	void (*send_func)(satp_connection_state*),
	void (*receive_callback)(satp_connection_state*, const uint8_t*, size_t))
{
	assert(ckey != NULL);
	assert(address != NULL);
	assert(send_func != NULL);
	assert(receive_callback != NULL);

	satp_kex_client_state* pcls;
	client_receiver_state* prcv;
	qsc_socket_exceptions serr;
	satp_errors err;

	pcls = NULL;
	prcv = NULL;

	if (ckey != NULL && address != NULL && send_func != NULL && receive_callback != NULL)
	{
		prcv = (client_receiver_state*)qsc_memutils_malloc(sizeof(client_receiver_state));
		pcls = (satp_kex_client_state*)qsc_memutils_malloc(sizeof(satp_kex_client_state));

		if (prcv != NULL && pcls != NULL)
		{
			qsc_memutils_clear(prcv, sizeof(client_receiver_state));
			qsc_memutils_clear(pcls, sizeof(satp_kex_client_state));

			prcv->pcns = (satp_connection_state*)qsc_memutils_malloc(sizeof(satp_connection_state));

			if (prcv->pcns != NULL)
			{
				prcv->callback = receive_callback;
				qsc_socket_client_initialize(&prcv->pcns->target);

				serr = qsc_socket_client_connect_ipv6(&prcv->pcns->target, address, port);

				if (serr == qsc_socket_exception_success)
				{
					/* initialize the client */
					err = satp_error_none;
					client_initialize(pcls, prcv->pcns, ckey);

					/* perform the key exchange */
					err = satp_kex_client_key_exchange(pcls, prcv->pcns);

					if (err == satp_error_none)
					{
						/* start the receive loop on a new thread */
						qsc_async_thread_create((void*)&client_receive_loop, prcv);

						/* start the send loop on the main thread */
						send_func(prcv->pcns);

						/* disconnect the socket */
						client_connection_dispose(prcv);
					}
				}
				else
				{
					err = satp_error_connection_failure;
				}
			}
			else
			{
				err = satp_error_allocation_failure;
			}
		}
		else
		{
			err = satp_error_allocation_failure;
		}
	}
	else
	{
		err = satp_error_invalid_input;
	}

	if (pcls != NULL)
	{
		qsc_memutils_clear(pcls, sizeof(satp_kex_client_state));
		qsc_memutils_alloc_free(pcls);
		pcls = NULL;
	}

	if (prcv != NULL)
	{
		if (prcv->pcns != NULL)
		{
			qsc_memutils_clear(prcv->pcns, sizeof(satp_connection_state));
			qsc_memutils_alloc_free(prcv->pcns);
			prcv->pcns = NULL;
		}

		prcv->callback = NULL;
		qsc_memutils_alloc_free(prcv);
		prcv = NULL;
	}

	return err;
}

void satp_client_connection_close(satp_connection_state* cns, satp_errors error)
{
	if (qsc_socket_is_connected(&cns->target) == true)
	{
		satp_network_packet resp = { 0 };
		uint8_t mresp[SATP_ERROR_SIZE] = { 0U };
		uint8_t spct[SATP_HEADER_SIZE + SATP_ERROR_SIZE] = { 0U };
		size_t plen;

		/* send a disconnect message */
		resp.pmessage = mresp;
		resp.flag = satp_flag_connection_terminate;
		resp.sequence = SATP_SEQUENCE_TERMINATOR;
		resp.msglen = 1;
		resp.pmessage[0U] = (uint8_t)error;
		plen = satp_packet_to_stream(&resp, spct);
		qsc_socket_send(&cns->target, spct, plen, qsc_socket_send_flag_none);

		/* close the socket */
		qsc_socket_close_socket(&cns->target);
	}

	/* dispose of resources */
	satp_connection_dispose(cns);
}
