#include "satp.h"
#include "acp.h"
#include "intutils.h"
#include "memutils.h"
#include "timestamp.h"

void satp_connection_close(satp_connection_state* cns, satp_errors err, bool notify)
{
	SATP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		if (qsc_socket_is_connected(&cns->target) == true)
		{
			if (notify == true)
			{
				satp_network_packet resp = { 0U };

				/* build a disconnect message */
				cns->txseq += 1U;
				resp.flag = satp_flag_error_condition;
				resp.sequence = cns->txseq;
				resp.msglen = SATP_MACTAG_SIZE + 1U;
				satp_packet_set_utc_time(&resp);

				/* tunnel gets encrypted message */
				if (cns->exflag == satp_flag_session_established)
				{
					uint8_t spct[SATP_HEADER_SIZE + SATP_MACTAG_SIZE + 1U] = { 0U };
					uint8_t pmsg[1U] = { 0U };

					resp.pmessage = spct + SATP_HEADER_SIZE;
					satp_packet_header_serialize(&resp, spct);
					/* the error is the message */
					pmsg[0U] = (uint8_t)err;

					/* add the header to aad */
					satp_cipher_set_associated(&cns->txcpr, spct, SATP_HEADER_SIZE);
					/* encrypt the message */
					satp_cipher_transform(&cns->txcpr, resp.pmessage, pmsg, sizeof(pmsg));
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
				else
				{
					/* pre-established phase */
					uint8_t spct[SATP_HEADER_SIZE + 1U] = { 0U };

					satp_packet_header_serialize(&resp, spct);
					spct[SATP_HEADER_SIZE] = (uint8_t)err;
					/* send the message */
					qsc_socket_send(&cns->target, spct, sizeof(spct), qsc_socket_send_flag_none);
				}
			}

			/* close the socket */
			qsc_socket_close_socket(&cns->target);
		}
	}
}

bool satp_decrypt_error_message(satp_errors* merr, satp_connection_state* cns, const uint8_t* message)
{
	SATP_ASSERT(cns != NULL);
	SATP_ASSERT(message != NULL);

	satp_network_packet pkt = { 0U };
	uint8_t dmsg[1U] = { 0U };
	const uint8_t* emsg;
	size_t mlen;
	satp_errors err;
	bool res;

	res = false;
	err = satp_error_invalid_input;

	if (cns->exflag == satp_flag_session_established)
	{
		satp_packet_header_deserialize(message, &pkt);
		emsg = message + SATP_HEADER_SIZE;

		if (cns != NULL && message != NULL)
		{
			cns->rxseq += 1;

			if (pkt.sequence == cns->rxseq)
			{
				if (cns->exflag == satp_flag_session_established)
				{
					/* anti-replay; verify the packet time */
					if (satp_packet_time_valid(&pkt) == true)
					{
						satp_cipher_set_associated(&cns->rxcpr, message, SATP_HEADER_SIZE);
						mlen = pkt.msglen - SATP_MACTAG_SIZE;

						if (mlen == 1U)
						{
							/* authenticate then decrypt the data */
							if (satp_cipher_transform(&cns->rxcpr, dmsg, emsg, mlen) == true)
							{
								err = (satp_errors)dmsg[0U];
								res = true;
							}
						}
					}
				}
			}
		}
	}

	*merr = err;

	return res;
}

void satp_connection_dispose(satp_connection_state* cns)
{
	SATP_ASSERT(cns != NULL);

	if (cns != NULL)
	{
		qsc_rcs_dispose(&cns->rxcpr);
		qsc_rcs_dispose(&cns->txcpr);
		qsc_memutils_clear((uint8_t*)&cns->target, sizeof(qsc_socket));
		cns->rxseq = 0;
		cns->txseq = 0;
		cns->cid = 0;
		cns->exflag = satp_flag_none;
		cns->receiver = false;
	}
}

satp_errors satp_decrypt_packet(satp_connection_state* cns, const satp_network_packet* packetin, uint8_t* message, size_t* msglen)
{
	SATP_ASSERT(cns != NULL);
	SATP_ASSERT(message != NULL);
	SATP_ASSERT(msglen != NULL);
	SATP_ASSERT(packetin != NULL);

	uint8_t hdr[SATP_HEADER_SIZE] = { 0 };
	satp_errors err;

	err = satp_error_invalid_input;

	if (cns != NULL && message != NULL && msglen != NULL && packetin != NULL)
	{
		cns->rxseq += 1;

		if (packetin->sequence == cns->rxseq)
		{
			if (cns->exflag == satp_flag_session_established)
			{
				/* anti-replay; verify the packet time */
				if (satp_packet_time_valid(packetin) == true)
				{
					/* serialize the header and add it to the ciphers associated data */
					satp_packet_header_serialize(packetin, hdr);
					satp_cipher_set_associated(&cns->rxcpr, hdr, SATP_HEADER_SIZE);
					*msglen = packetin->msglen - SATP_MACTAG_SIZE;

					/* authenticate then decrypt the data */
					if (satp_cipher_transform(&cns->rxcpr, message, packetin->pmessage, *msglen) == true)
					{
						err = satp_error_none;
					}
					else
					{
						err = satp_error_cipher_auth_failure;
					}
				}
				else
				{
					err = satp_error_packet_expired;
				}
			}
			else if (cns->exflag != satp_flag_keepalive_request)
			{
				err = satp_error_channel_down;
			}
		}
		else
		{
			err = satp_error_unsequenced;
		}
	}

	if (err != satp_error_none)
	{
		*msglen = 0;
	}

	return err;
}

satp_errors satp_encrypt_packet(satp_connection_state* cns, const uint8_t* message, size_t msglen, satp_network_packet* packetout)
{
	SATP_ASSERT(cns != NULL);
	SATP_ASSERT(message != NULL);
	SATP_ASSERT(packetout != NULL);

	satp_errors err;

	err = satp_error_invalid_input;

	if (cns != NULL && message != NULL && packetout != NULL)
	{
		if (cns->exflag == satp_flag_session_established)
		{
			uint8_t hdr[SATP_HEADER_SIZE] = { 0U };

			/* assemble the encryption packet */
			cns->txseq += 1;
			packetout->flag = satp_flag_encrypted_message;
			packetout->msglen = (uint32_t)msglen + SATP_MACTAG_SIZE;
			packetout->sequence = cns->txseq;
			/* anti-replay; set the packet utc time field */
			satp_packet_set_utc_time(packetout);
			/* serialize the header and add it to the ciphers associated data */
			satp_packet_header_serialize(packetout, hdr);
			satp_cipher_set_associated(&cns->txcpr, hdr, SATP_HEADER_SIZE);
			/* encrypt the message */
			satp_cipher_transform(&cns->txcpr, packetout->pmessage, message, msglen);

			err = satp_error_none;
		}
		else
		{
			err = satp_error_channel_down;
		}
	}

	return err;
}

void satp_deserialize_device_key(satp_device_key* dkey, const uint8_t* input)
{
	SATP_ASSERT(dkey != NULL);
	SATP_ASSERT(input != NULL);

	size_t pos;

	if (dkey != NULL && input != NULL)
	{
		qsc_memutils_copy(dkey->kid, input, SATP_KID_SIZE);
		pos = SATP_KID_SIZE;
		qsc_memutils_copy(dkey->stc, input + pos, SATP_SKEY_SIZE);
		pos += SATP_SKEY_SIZE;
		dkey->expiration = qsc_intutils_le8to64(input + pos);
		pos += SATP_EXPIRATION_SIZE;
		qsc_memutils_copy(dkey->ktree, input + pos, SATP_DKEY_SIZE * SATP_KEY_TREE_COUNT);
	}
}

void satp_serialize_device_key(uint8_t* output, const satp_device_key* dkey)
{
	SATP_ASSERT(output != NULL);
	SATP_ASSERT(dkey != NULL);

	size_t pos;

	if (output != NULL && dkey != NULL)
	{
		qsc_memutils_copy(output, dkey->kid, SATP_KID_SIZE);
		pos = SATP_KID_SIZE;
		qsc_memutils_copy(output + pos, dkey->stc, SATP_SKEY_SIZE);
		pos += SATP_SKEY_SIZE;
		qsc_intutils_le64to8(output + pos, dkey->expiration);
		pos += SATP_EXPIRATION_SIZE;
		qsc_memutils_copy(output + pos, dkey->ktree, SATP_DKEY_SIZE * SATP_KEY_TREE_COUNT);
	}
}

void satp_deserialize_master_key(satp_master_key* mkey, const uint8_t* input)
{
	SATP_ASSERT(mkey != NULL);
	SATP_ASSERT(input != NULL);

	size_t pos;

	if (mkey != NULL && input != NULL)
	{
		qsc_memutils_copy(mkey->mid, input, SATP_MID_SIZE);
		pos = SATP_MID_SIZE;
		qsc_memutils_copy(mkey->mdk, input + pos, SATP_MKEY_SIZE);
		pos += SATP_MKEY_SIZE;
		mkey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void satp_serialize_master_key(uint8_t* output, const satp_master_key* mkey)
{
	SATP_ASSERT(output != NULL);
	SATP_ASSERT(mkey != NULL);

	size_t pos;

	if (output != NULL && mkey != NULL)
	{
		qsc_memutils_copy(output, mkey->mid, SATP_MID_SIZE);
		pos = SATP_MID_SIZE;
		qsc_memutils_copy(output + pos, mkey->mdk, SATP_MKEY_SIZE);
		pos += SATP_MKEY_SIZE;
		qsc_intutils_le64to8(output + pos, mkey->expiration);
	}
}

void satp_deserialize_server_key(satp_server_key* skey, const uint8_t* input)
{
	SATP_ASSERT(skey != NULL);
	SATP_ASSERT(input != NULL);

	size_t pos;

	if (skey != NULL && input != NULL)
	{
		qsc_memutils_copy(skey->sid, input, SATP_SID_SIZE);
		pos = SATP_SID_SIZE;
		qsc_memutils_copy(skey->stc, input + pos, SATP_SKEY_SIZE);
		pos += SATP_SKEY_SIZE;
		qsc_memutils_copy(skey->sdk, input + pos, SATP_SKEY_SIZE);
		pos += SATP_SKEY_SIZE;
		skey->expiration = qsc_intutils_le8to64(input + pos);
	}
}

void satp_serialize_server_key(uint8_t* output, const satp_server_key* skey)
{
	SATP_ASSERT(output != NULL);
	SATP_ASSERT(skey != NULL);

	size_t pos;

	if (output != NULL && skey != NULL)
	{
		qsc_memutils_copy(output, skey->sid, SATP_SID_SIZE);
		pos = SATP_SID_SIZE;
		qsc_memutils_copy(output + pos, skey->stc, SATP_SKEY_SIZE);
		pos += SATP_SKEY_SIZE;
		qsc_memutils_copy(output + pos, skey->sdk, SATP_SKEY_SIZE);
		pos += SATP_SKEY_SIZE;
		qsc_intutils_le64to8(output + pos, skey->expiration);
	}
}

void satp_increment_device_key(uint8_t* sdkey)
{
	uint8_t* kid;
	uint32_t ctr;

	/* get the key id */
	kid = sdkey;
	ctr = qsc_intutils_be8to32(kid + SATP_DID_SIZE);
	/* clear the key at the current position */
	qsc_memutils_clear(sdkey + SATP_KID_SIZE + SATP_SKEY_SIZE + SATP_EXPIRATION_SIZE + (ctr * SATP_DKEY_SIZE), SATP_DKEY_SIZE);
	/* increment and write the new key index to the kid */
	++ctr;
	qsc_intutils_be32to8(sdkey + SATP_DID_SIZE, ctr);
}

const char* satp_get_error_description(satp_messages message)
{
	const char* dsc;

	dsc = NULL;

	if (message < SATP_MESSAGE_STRING_DEPTH && message >= 0)
	{
		dsc = SATP_MESSAGE_STRINGS[(size_t)message];

	}

	return dsc;
}

void satp_log_system_error(satp_errors err)
{
	char mtmp[SATP_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* pmsg;

	pmsg = satp_error_to_string(err);
	perr = satp_get_error_description(satp_messages_system_message);

	qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
	qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);

	satp_logger_write(mtmp);
}

void satp_log_error(satp_messages emsg, qsc_socket_exceptions err, const char* msg)
{
	SATP_ASSERT(msg != NULL);

	char mtmp[SATP_ERROR_STRING_WIDTH * 2] = { 0 };
	const char* perr;
	const char* phdr;
	const char* pmsg;

	pmsg = satp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);
			qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
			satp_logger_write(mtmp);
		}
		else
		{
			satp_logger_write(pmsg);
		}
	}

	phdr = satp_get_error_description(satp_messages_socket_message);
	perr = qsc_socket_error_to_string(err);

	if (pmsg != NULL && perr != NULL)
	{
		qsc_stringutils_clear_string(mtmp);
		qsc_stringutils_copy_string(mtmp, sizeof(mtmp), phdr);
		qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), perr);
		satp_logger_write(mtmp);
	}
}

void satp_log_message(satp_messages emsg)
{
	const char* msg = satp_get_error_description(emsg);

	if (msg != NULL)
	{
		satp_logger_write(msg);
	}
}

void satp_log_write(satp_messages emsg, const char* msg)
{
	SATP_ASSERT(msg != NULL);

	const char* pmsg = satp_get_error_description(emsg);

	if (pmsg != NULL)
	{
		if (msg != NULL)
		{
			char mtmp[SATP_ERROR_STRING_WIDTH + 1U] = { 0 };

			qsc_stringutils_copy_string(mtmp, sizeof(mtmp), pmsg);

			if ((qsc_stringutils_string_size(msg) + qsc_stringutils_string_size(mtmp)) < sizeof(mtmp))
			{
				qsc_stringutils_concat_strings(mtmp, sizeof(mtmp), msg);
				satp_logger_write(mtmp);
			}
		}
		else
		{
			satp_logger_write(pmsg);
		}
	}
}

void satp_packet_error_message(satp_network_packet* packet, satp_errors error)
{
	SATP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->flag = satp_flag_error_condition;
		packet->msglen = SATP_ERROR_MESSAGE_SIZE;
		packet->sequence = SATP_ERROR_SEQUENCE;
		packet->pmessage[0] = (uint8_t)error;
		satp_packet_set_utc_time(packet);
	}
}

const char* satp_error_to_string(satp_errors error)
{
	const char* dsc;

	dsc = NULL;

	if ((uint32_t)error < SATP_ERROR_STRING_DEPTH)
	{
		dsc = SATP_ERROR_STRINGS[(size_t)error];
	}

	return dsc;
}

bool satp_extract_device_key(uint8_t* dk, const uint8_t* sk, const uint8_t* kid)
{
	SATP_ASSERT(dk != NULL);
	SATP_ASSERT(sk != NULL);
	SATP_ASSERT(kid != NULL);

	uint32_t kidx;
	bool res;

	res = false;

	if (dk != NULL && sk != NULL && kid != NULL)
	{
		/* get the current key index and key pointer */
		kidx = qsc_intutils_be8to32(kid + SATP_DID_SIZE);

		if (kidx < SATP_KEY_TREE_COUNT)
		{
			qsc_cshake256_compute(dk, SATP_DKEY_SIZE, sk, SATP_SKEY_SIZE, NULL, 0U, kid, SATP_KID_SIZE);
			res = true;
		}
	}

	return res;
}

void satp_generate_device_key(satp_device_key* dkey, const satp_server_key* skey, const uint8_t* did)
{
	SATP_ASSERT(dkey != NULL);
	SATP_ASSERT(skey != NULL);
	SATP_ASSERT(did != NULL);

	if (dkey != NULL && skey != NULL && did != NULL)
	{
		qsc_memutils_copy(dkey->kid, did, SATP_DID_SIZE);
		qsc_memutils_copy(dkey->stc, skey->stc, SATP_SKEY_SIZE);
		dkey->expiration = skey->expiration;

		for (size_t i = 0U; i < SATP_KEY_TREE_COUNT; ++i)
		{
			qsc_cshake256_compute(dkey->ktree + (i * SATP_DKEY_SIZE), SATP_DKEY_SIZE, skey->sdk, SATP_SKEY_SIZE, NULL, 0U, dkey->kid, SATP_KID_SIZE);
			qsc_intutils_be8increment(dkey->kid + SATP_DID_SIZE, SATP_KEY_ID_SIZE);
		}

		/* reset the counter */
		qsc_memutils_clear(dkey->kid + SATP_DID_SIZE, SATP_KEY_ID_SIZE);
	}
}

bool satp_generate_master_key(satp_master_key* mkey, const uint8_t* mid)
{
	SATP_ASSERT(mkey != NULL);
	SATP_ASSERT(mid != NULL);

	uint8_t rnd[SATP_MKEY_SIZE] = { 0U };
	bool res;

	res = false;

	if (mkey != NULL && mid != NULL)
	{
		res = qsc_acp_generate(rnd, sizeof(rnd));

		if (res == true)
		{
			qsc_memutils_copy(mkey->mdk, rnd, SATP_MKEY_SIZE);
			qsc_memutils_clear(rnd, SATP_MID_SIZE);
			qsc_memutils_copy(mkey->mid, mid, SATP_MID_SIZE);
			mkey->expiration = qsc_timestamp_epochtime_seconds() + SATP_KEY_DURATION_SECONDS;
		}
	}

	return res;
}

bool satp_generate_server_key(satp_server_key* skey, const satp_master_key* mkey, const uint8_t* sid)
{
	SATP_ASSERT(skey != NULL);
	SATP_ASSERT(mkey != NULL);
	SATP_ASSERT(sid != NULL);

	bool res;

	res = false;

	if (skey != NULL && mkey != NULL && sid != NULL)
	{
		res = qsc_acp_generate(skey->stc, SATP_SKEY_SIZE);

		if (res == true)
		{
			qsc_cshake256_compute(skey->sdk, SATP_SKEY_SIZE, mkey->mdk, SATP_MKEY_SIZE, (uint8_t*)SATP_CONFIG_STRING, SATP_CONFIG_SIZE, sid, SATP_SID_SIZE);
			qsc_memutils_copy(skey->sid, sid, SATP_SID_SIZE);
			skey->expiration = mkey->expiration;
			res = true;
		}
	}

	return res;
}

void satp_packet_clear(satp_network_packet* packet)
{
	SATP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		if (packet->msglen != 0U)
		{
			qsc_memutils_clear(packet->pmessage, packet->msglen);
		}

		packet->flag = (uint8_t)satp_flag_none;
		packet->msglen = 0U;
		packet->sequence = 0U;
	}
}

void satp_packet_header_create(satp_network_packet* packetout, satp_flags flag, uint64_t sequence, uint32_t msglen)
{
	packetout->flag = flag;
	packetout->sequence = sequence;
	packetout->msglen = msglen;
	/* set the packet creation time */
	satp_packet_set_utc_time(packetout);
}

void satp_packet_header_deserialize(const uint8_t* header, satp_network_packet* packet)
{
	SATP_ASSERT(header != NULL);
	SATP_ASSERT(packet != NULL);

	if (header != NULL && packet != NULL)
	{
		packet->flag = header[0U];
		packet->msglen = qsc_intutils_le8to32(header + sizeof(uint8_t));
		packet->sequence = qsc_intutils_le8to64(header + sizeof(uint8_t) + sizeof(uint32_t));
		packet->utctime = qsc_intutils_le8to64(header + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t));
	}
}

void satp_packet_header_serialize(const satp_network_packet* packet, uint8_t* header)
{
	SATP_ASSERT(packet != NULL);
	SATP_ASSERT(header != NULL);

	if (packet != NULL && header != NULL)
	{
		header[0U] = packet->flag;
		qsc_intutils_le32to8(header + sizeof(uint8_t), packet->msglen);
		qsc_intutils_le64to8(header + sizeof(uint8_t) + sizeof(uint32_t), packet->sequence);
		qsc_intutils_le64to8(header + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t), packet->utctime);
	}
}

satp_errors satp_packet_header_validate(const satp_network_packet* packetin, satp_flags pktflag, uint64_t sequence, uint32_t msglen)
{
	satp_errors merr;

	if (packetin->flag == satp_flag_error_condition)
	{
		merr = (satp_errors)packetin->pmessage[0U];
	}
	else
	{
		if (satp_packet_time_valid(packetin) == true)
		{
			if (packetin->msglen == msglen)
			{
				if (packetin->sequence == sequence)
				{
					if (packetin->flag == pktflag)
					{
						merr = satp_error_none;
					}
					else
					{
						merr = satp_error_invalid_request;
					}
				}
				else
				{
					merr = satp_error_packet_unsequenced;
				}
			}
			else
			{
				merr = satp_error_receive_failure;
			}
		}
		else
		{
			merr = satp_error_message_time_invalid;
		}
	}

	return merr;
}

void satp_packet_set_utc_time(satp_network_packet* packet)
{
	SATP_ASSERT(packet != NULL);

	if (packet != NULL)
	{
		packet->utctime = qsc_timestamp_datetime_utc();
	}
}

bool satp_packet_time_valid(const satp_network_packet* packet)
{
	SATP_ASSERT(packet != NULL);

	uint64_t ltime;
	bool res;

	res = false;

	if (packet != NULL)
	{
		ltime = qsc_timestamp_datetime_utc();
		res = (ltime >= packet->utctime - SATP_PACKET_TIME_THRESHOLD && ltime <= packet->utctime + SATP_PACKET_TIME_THRESHOLD);
	}

	return res;
}

size_t satp_packet_to_stream(const satp_network_packet* packet, uint8_t* pstream)
{
	SATP_ASSERT(packet != NULL);
	SATP_ASSERT(pstream != NULL);

	size_t res;

	res = 0;

	if (packet != NULL && pstream != NULL)
	{
		pstream[0U] = packet->flag;
		qsc_intutils_le32to8(pstream + sizeof(uint8_t), packet->msglen);
		qsc_intutils_le64to8(pstream + sizeof(uint8_t) + sizeof(uint32_t), packet->sequence);
		qsc_intutils_le64to8(pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t), packet->utctime);

		if (packet->msglen <= SATP_MESSAGE_MAX)
		{
			qsc_memutils_copy(pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t), (const uint8_t*)packet->pmessage, packet->msglen);
			res = SATP_HEADER_SIZE + packet->msglen;
		}
	}

	return res;
}

void satp_send_network_error(const qsc_socket* sock, satp_errors error)
{
	SATP_ASSERT(sock != NULL);

	if (qsc_socket_is_connected(sock) == true)
	{
		satp_network_packet resp = { 0 };
		uint8_t spct[SATP_HEADER_SIZE + SATP_ERROR_MESSAGE_SIZE] = { 0 };

		resp.pmessage = spct + SATP_HEADER_SIZE;
		satp_packet_error_message(&resp, error);
		satp_packet_header_serialize(&resp, spct);
		qsc_socket_send(sock, spct, sizeof(spct), qsc_socket_send_flag_none);
	}
}

void satp_stream_to_packet(const uint8_t* pstream, satp_network_packet* packet)
{
	SATP_ASSERT(packet != NULL);
	SATP_ASSERT(pstream != NULL);

	if (packet != NULL && pstream != NULL)
	{
		packet->flag = pstream[0U];
		packet->msglen = qsc_intutils_le8to32(pstream + sizeof(uint8_t));
		packet->sequence = qsc_intutils_le8to64(pstream + sizeof(uint8_t) + sizeof(uint32_t));
		packet->utctime = qsc_intutils_le8to64(pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t));

		if (packet->msglen <= SATP_MESSAGE_MAX)
		{
			qsc_memutils_copy(packet->pmessage, pstream + sizeof(uint8_t) + sizeof(uint32_t) + sizeof(uint64_t) + sizeof(uint64_t), packet->msglen);
		}
	}
}
