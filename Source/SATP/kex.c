#include "kex.h"
#include "acp.h"

#define SATP_CONNECT_REQUEST_MESSAGE_SIZE (SATP_KID_SIZE + SATP_STOK_SIZE)
#define SATP_CONNECT_REQUEST_PACKET_SIZE (SATP_HEADER_SIZE + SATP_CONNECT_REQUEST_MESSAGE_SIZE)
#define SATP_CLIENT_PACKET_BUFFER_SIZE (SATP_CONNECT_REQUEST_PACKET_SIZE)
#define SATP_CONNECT_RESPONSE_MESSAGE_SIZE (SATP_HASH_SIZE + SATP_MACTAG_SIZE)
#define SATP_CONNECT_RESPONSE_PACKET_SIZE (SATP_HEADER_SIZE + SATP_CONNECT_RESPONSE_MESSAGE_SIZE)

static void client_kex_reset(satp_kex_client_state* cls)
{
	SATP_ASSERT(cls != NULL);

	if (cls != NULL)
	{
		qsc_memutils_clear(cls->dk, SATP_DKEY_SIZE);
		qsc_memutils_clear(cls->hc, SATP_HASH_SIZE);
		qsc_memutils_clear(cls->hp, SATP_HASH_SIZE);
		qsc_memutils_clear(cls->kid, SATP_KID_SIZE);
		qsc_memutils_clear(cls->stc, SATP_SALT_SIZE);
		cls->kidx = 0;
		cls->expiration = 0U;
	}
}

satp_errors client_connect_request(satp_kex_client_state* cls, satp_connection_state* cns, satp_network_packet* packetout)
{
	SATP_ASSERT(cls != NULL);
	SATP_ASSERT(cns != NULL);
	SATP_ASSERT(packetout != NULL);

	uint8_t kid[SATP_KID_SIZE] = { 0U };
	uint8_t nh[SATP_STOK_SIZE] = { 0U };
	uint8_t prnd[(SATP_SKEY_SIZE + SATP_NONCE_SIZE) * 2U] = { 0U };
	satp_errors err;

	if (cls != NULL && cns != NULL && packetout != NULL)
	{
		if (qsc_acp_generate(nh, SATP_STOK_SIZE) == true)
		{
			/* assemble the device id */
			qsc_memutils_copy(kid, cls->kid, SATP_KID_SIZE);

			/* generate the session keys */
			qsc_cshake256_compute(prnd, sizeof(prnd), cls->dk, SATP_DKEY_SIZE, (uint8_t*)SATP_CONFIG_STRING, SATP_CONFIG_SIZE, nh, SATP_STOK_SIZE);
			
			/* compute the session hash */
			qsc_cshake256_compute(cls->hc, SATP_HASH_SIZE, nh, SATP_STOK_SIZE, cls->dk, SATP_DKEY_SIZE, cls->stc, SATP_SALT_SIZE);

			/* assemble the connection-request packet */
			qsc_memutils_copy(packetout->pmessage, kid, SATP_KID_SIZE);
			qsc_memutils_copy(packetout->pmessage + SATP_KID_SIZE, nh, SATP_STOK_SIZE);

			/* erase the nonce */
			qsc_memutils_clear(nh, SATP_STOK_SIZE);

			/* assemble the connect-response packet */
			satp_packet_header_create(packetout, satp_flag_connect_request, cns->txseq, SATP_CONNECT_REQUEST_MESSAGE_SIZE);

			/* initialize the symmetric cipher, and raise client channel-1 tx */
			qsc_rcs_keyparams kp = { 0 };
			kp.key = prnd;
			kp.keylen = SATP_SKEY_SIZE;
			kp.nonce = prnd + SATP_SKEY_SIZE;
			kp.info = NULL;
			kp.infolen = 0U;
			qsc_rcs_initialize(&cns->txcpr, &kp, true);

			/* initialize the symmetric cipher, and raise client channel-1 rx */
			kp.key = prnd + SATP_SKEY_SIZE + SATP_NONCE_SIZE;
			kp.keylen = SATP_SKEY_SIZE;
			kp.nonce = prnd + SATP_SKEY_SIZE + SATP_NONCE_SIZE + SATP_SKEY_SIZE;
			kp.info = NULL;
			kp.infolen = 0U;
			qsc_rcs_initialize(&cns->rxcpr, &kp, false);

			/* clear the keys */
			qsc_memutils_clear((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));
			qsc_memutils_clear(prnd, sizeof(prnd));

			cns->exflag = satp_flag_connect_request;
			err = satp_error_none;
		}
		else
		{
			cns->exflag = satp_flag_none;
			err = satp_error_random_failure;
		}
	}
	else
	{
		err = satp_error_general_failure;
	}

	return err;
}

static void server_kex_reset(satp_kex_server_state* svs)
{
	SATP_ASSERT(svs != NULL);

	if (svs != NULL)
	{
		qsc_memutils_clear(svs->sid, SATP_SID_SIZE);
		qsc_memutils_clear(svs->hc, SATP_HASH_SIZE);
		qsc_memutils_clear(svs->sdk, SATP_SKEY_SIZE);
		qsc_memutils_clear(svs->sp, SATP_HASH_SIZE);
		qsc_memutils_clear(svs->stc, SATP_SALT_SIZE);
		svs->expiration = 0U;
	}
}

static satp_errors server_connect_response(satp_kex_server_state* svs, satp_connection_state* cns, const satp_network_packet* packetin, satp_network_packet* packetout)
{
	uint8_t dk[SATP_DKEY_SIZE] = { 0U };
	uint8_t kid[SATP_KID_SIZE] = { 0U };
	uint8_t nh[SATP_STOK_SIZE] = { 0U };
	uint8_t prnd[(SATP_SKEY_SIZE + SATP_NONCE_SIZE) * 2U] = { 0U };
	uint8_t shdr[SATP_HEADER_SIZE] = { 0U };
	satp_errors err;

	if (svs != NULL && cns != NULL)
	{
		err = satp_error_none;

		/* copy the device id, and configuration strings */
		qsc_memutils_copy(kid, packetin->pmessage, SATP_KID_SIZE);
		qsc_memutils_copy(nh, packetin->pmessage + SATP_KID_SIZE, SATP_STOK_SIZE);

		/* generate the clients key */
		if (satp_extract_device_key(dk, svs->sdk, kid) == true)
		{
			qsc_cshake256_compute(prnd, sizeof(prnd), dk, SATP_DKEY_SIZE, (uint8_t*)SATP_CONFIG_STRING, SATP_CONFIG_SIZE, nh, SATP_STOK_SIZE);

			/* initialize the symmetric cipher, and raise client channel-1 rx */
			qsc_rcs_keyparams kp = { 0 };
			kp.key = prnd;
			kp.keylen = SATP_SKEY_SIZE;
			kp.nonce = prnd + SATP_SKEY_SIZE;
			kp.info = NULL;
			kp.infolen = 0U;
			qsc_rcs_initialize(&cns->rxcpr, &kp, false);

			/* initialize the symmetric cipher, and raise client channel-1 tx */
			kp.key = prnd + SATP_SKEY_SIZE + SATP_NONCE_SIZE;
			kp.keylen = SATP_SKEY_SIZE;
			kp.nonce = prnd + SATP_SKEY_SIZE + SATP_NONCE_SIZE + SATP_SKEY_SIZE;
			kp.info = NULL;
			kp.infolen = 0U;
			qsc_rcs_initialize(&cns->txcpr, &kp, true);

			/* clear the keys */
			qsc_memutils_clear((uint8_t*)&kp, sizeof(qsc_rcs_keyparams));
			qsc_memutils_clear(prnd, sizeof(prnd));

			/* compute the session hash */
			qsc_cshake256_compute(svs->hc, SATP_HASH_SIZE, nh, SATP_STOK_SIZE, dk, SATP_SKEY_SIZE, svs->stc, SATP_SALT_SIZE);

			/* assemble the connect-response packet */
			satp_packet_header_create(packetout, satp_flag_connect_response, cns->txseq, SATP_CONNECT_RESPONSE_MESSAGE_SIZE);

			/* encrypt and add schash to establish request */
			satp_packet_header_serialize(packetout, shdr);
			qsc_rcs_set_associated(&cns->txcpr, shdr, SATP_HEADER_SIZE);
			qsc_rcs_transform(&cns->txcpr, packetout->pmessage, svs->hc, SATP_HASH_SIZE);

			cns->exflag = satp_flag_connect_request;
			err = satp_error_none;
		}
		else
		{
			err = satp_error_key_expired;
		}
	}
	else
	{
		err = satp_error_general_failure;
	}

	return err;
}

satp_errors satp_kex_client_key_exchange(satp_kex_client_state* cls, satp_connection_state* cns)
{
	satp_network_packet reqt = { 0 };
	satp_network_packet resp = { 0 };
	uint8_t mreqt[SATP_CONNECT_REQUEST_PACKET_SIZE] = { 0U };
	uint8_t mresp[SATP_CONNECT_RESPONSE_PACKET_SIZE] = { 0U };
	size_t rlen;
	size_t slen;
	satp_errors err;

	reqt.pmessage = mreqt + SATP_HEADER_SIZE;
	/* create the connection request packet */
	err = client_connect_request(cls, cns, &reqt);
	/* convert the header to bytes */
	satp_packet_header_serialize(&reqt, mreqt);

	if (err == satp_error_none)
	{
		/* send the connection request */
		slen = qsc_socket_send(&cns->target, mreqt, SATP_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_send_flag_none);
		/* clear the request packet */
		satp_packet_clear(&reqt);

		if (slen == SATP_CONNECT_REQUEST_PACKET_SIZE)
		{
			cns->txseq += 1U;
			/* blocking receive waits for server */
			rlen = qsc_socket_receive(&cns->target, mresp, SATP_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_receive_flag_wait_all);
			/* convert server response to packet */
			satp_packet_header_deserialize(mresp, &resp);
			resp.pmessage = mresp + SATP_HEADER_SIZE;
			/* validate the packet header */
			err = satp_packet_header_validate(&resp, satp_flag_connect_response, cns->rxseq, SATP_CONNECT_RESPONSE_MESSAGE_SIZE);

			if (err == satp_error_none)
			{
				uint8_t phash[SATP_HASH_SIZE] = { 0U };
				uint8_t shdr[SATP_HEADER_SIZE] = { 0U };

				/* add the header to aead */
				satp_packet_header_serialize(&resp, shdr);
				qsc_rcs_set_associated(&cns->rxcpr, shdr, SATP_HEADER_SIZE);

				/* decrypt the message */
				if (qsc_rcs_transform(&cns->rxcpr, phash, resp.pmessage, SATP_HASH_SIZE) == true)
				{
					/* verify the server schash */
					if (qsc_intutils_verify(phash, cls->hc, SATP_HASH_SIZE) == 0)
					{
						cns->rxseq += 1U;
					}
					else
					{
						err = satp_error_authentication_failure;
					}
				}
				else
				{
					err = satp_error_decryption_failure;
				}
			}
		}
		else
		{
			err = satp_error_transmit_failure;
		}
	}
	else
	{
		err = satp_error_connection_failure;
	}

	client_kex_reset(cls);

	if (err == satp_error_none)
	{
		cns->exflag = satp_flag_session_established;
	}
	else
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			satp_send_network_error(&cns->target, err);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		satp_connection_dispose(cns);
	}

	return err;
}

satp_errors satp_kex_server_key_exchange(satp_kex_server_state* svs, satp_connection_state* cns)
{
	satp_network_packet reqt = { 0 };
	satp_network_packet resp = { 0 };
	uint8_t mreqt[SATP_CONNECT_REQUEST_PACKET_SIZE] = { 0 };
	uint8_t mresp[SATP_CONNECT_RESPONSE_PACKET_SIZE] = { 0 };
	size_t rlen;
	size_t slen;
	satp_errors err;

	err = satp_error_none;

	/* blocking receive waits for client */
	rlen = qsc_socket_receive(&cns->target, mreqt, SATP_CONNECT_REQUEST_PACKET_SIZE, qsc_socket_receive_flag_wait_all);

	if (rlen == SATP_CONNECT_REQUEST_PACKET_SIZE)
	{
		/* convert server response to packet */
		satp_packet_header_deserialize(mreqt, &reqt);
		reqt.pmessage = mreqt + SATP_HEADER_SIZE;

		/* validate the packet header */
		err = satp_packet_header_validate(&reqt, satp_flag_connect_request, cns->rxseq, SATP_CONNECT_REQUEST_MESSAGE_SIZE);

		if (err == satp_error_none)
		{
			cns->rxseq += 1U;
			resp.pmessage = mresp + SATP_HEADER_SIZE;
			/* create the connection request packet */
			err = server_connect_response(svs, cns, &reqt, &resp);
			/* convert the header to bytes */
			satp_packet_header_serialize(&resp, mresp);
		}
	}
	else
	{
		err = satp_error_receive_failure;
	}

	if (err == satp_error_none)
	{
		/* send the connection response */
		slen = qsc_socket_send(&cns->target, mresp, SATP_CONNECT_RESPONSE_PACKET_SIZE, qsc_socket_send_flag_none);

		if (slen == SATP_CONNECT_RESPONSE_PACKET_SIZE)
		{
			cns->txseq += 1U;
		}
		else
		{
			err = satp_error_transmit_failure;
		}
	}

	server_kex_reset(svs);

	if (err == satp_error_none)
	{
		cns->exflag = satp_flag_session_established;
	}
	else
	{
		if (cns->target.connection_status == qsc_socket_state_connected)
		{
			satp_send_network_error(&cns->target, err);
			qsc_socket_shut_down(&cns->target, qsc_socket_shut_down_flag_both);
		}

		satp_connection_dispose(cns);
	}

	return err;
}
