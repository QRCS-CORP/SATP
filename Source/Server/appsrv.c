#include "appsrv.h"
#include "satp.h"
#include "server.h"
#include "acp.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "ipinfo.h"
#include "memutils.h"
#include "netutils.h"
#include "sha3.h"
#include "socketserver.h"
#include "stringutils.h"

static void server_print_error(satp_errors error)
{
	const char* msg;

	msg = satp_error_to_string(error);

	if (msg != NULL)
	{
		qsc_consoleutils_print_safe("server> ");
		qsc_consoleutils_print_line(msg);
	}
}

static void server_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			qsc_consoleutils_print_safe("server> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_line("server> ");
		}
	}
}

static void server_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0U)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void server_print_prompt(void)
{
	qsc_consoleutils_print_safe("server> ");
}

static void server_print_passphrase(char* pass)
{
	qsc_consoleutils_print_safe("server> ");
	qsc_consoleutils_print_safe("The user passphrase has been generated: ");
	qsc_consoleutils_print_line(pass);
}

static void server_print_banner(void)
{
	qsc_consoleutils_print_line("*************************************************************");
	qsc_consoleutils_print_line("* SATP: Symmetric Authenticated Tunneling Protocol Listener *");
	qsc_consoleutils_print_line("*                                                           *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0a (A1)                                 *");
	qsc_consoleutils_print_line("* Date:      March 14, 2025                                 *");
	qsc_consoleutils_print_line("* Contact:   contact@qrcscorp.ca                            *");
	qsc_consoleutils_print_line("*************************************************************");
	qsc_consoleutils_print_line("");
}

static bool server_get_storage_path(char* fpath, size_t pathlen)
{
	bool res;

	qsc_folderutils_get_directory(qsc_folderutils_directories_user_documents, fpath);
	qsc_folderutils_append_delimiter(fpath);
	qsc_stringutils_concat_strings(fpath, pathlen, SATP_APP_PATH);
	res = qsc_folderutils_directory_exists(fpath);

	if (res == false)
	{
		res = qsc_folderutils_create_directory(fpath);
	}

	return res;
}

static bool server_prikey_exists(void)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(fpath, sizeof(fpath));

	if (res == true)
	{
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, sizeof(fpath), SATP_SRVKEY_NAME);

		res = qsc_fileutils_exists(fpath);
	}

	return res;
}

static void server_create_path(char* fpath, const char* fname)
{
	char dir[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	res = server_get_storage_path(dir, sizeof(dir));

	if (res == true)
	{
		qsc_stringutils_clear_string(fpath);
		qsc_stringutils_copy_string(fpath, QSC_SYSTEM_MAX_PATH, dir);
		qsc_folderutils_append_delimiter(fpath);
		qsc_stringutils_concat_strings(fpath, QSC_SYSTEM_MAX_PATH, fname);
	}
}

static bool server_fetch_user_credential(uint8_t* credential, const uint8_t* did)
{
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	uint8_t cred[SATP_DID_SIZE + SATP_HASH_SIZE] = { 0U };
	bool res;

	/* in a real-world implementation, the callback would query a database
	   that fetches the passphrase hash from a database using the device id,
	   but in the example, a single user is added to demonstrate the mechanism. */

	server_create_path(fpath, SATP_USERDB_NAME);
	res = qsc_fileutils_copy_file_to_stream(fpath, (char*)cred, sizeof(cred));

	if (res == true)
	{
		const uint8_t* pdid;
		const uint8_t* pcred;

		pdid = cred;
		pcred = cred + SATP_DID_SIZE;
		res = qsc_intutils_verify(did, pdid, SATP_DID_SIZE) == 0;

		if (res == true)
		{
			qsc_memutils_copy(credential, pcred, SATP_HASH_SIZE);
		}
	}

	return res;
}

static bool server_key_dialogue(satp_server_key* skey, uint8_t keyid[SATP_DID_SIZE])
{
	uint8_t sskey[SATP_SKEY_ENCODED_SIZE] = { 0U };
	char fpath[QSC_SYSTEM_MAX_PATH] = { 0 };
	bool res;

	if (server_prikey_exists() == true)
	{
		server_create_path(fpath, SATP_SRVKEY_NAME);
		res = qsc_fileutils_copy_file_to_stream(fpath, (char*)sskey, sizeof(sskey));

		if (res == true)
		{
			satp_deserialize_server_key(skey, sskey);
			server_print_message("The server-key has been loaded.");
		}
		else
		{
			server_print_message("Could not load the server-key, aborting startup.");
		}

		/* clean up */
		qsc_memutils_clear(sskey, sizeof(sskey));
	}
	else
	{
		satp_device_key dkey = { 0U };
		satp_master_key mkey = { 0U };
		uint8_t sdkey[SATP_DKEY_ENCODED_SIZE] = { 0U };
		uint8_t smkey[SATP_MKEY_ENCODED_SIZE] = { 0U };
		char upass[SATP_DID_SIZE + SATP_HASH_SIZE + 1U] = { 0 };

		server_print_message("The server-key was not detected, generating new master/server keys.");

		/* generate a random master key id */
		qsc_acp_generate(keyid, SATP_MID_SIZE);
		/* generate the master key */
		satp_generate_master_key(&mkey, keyid);

		/* generate a random server key id */
		qsc_acp_generate(keyid + SATP_MID_SIZE, SATP_BRANCH_ID_SIZE);
		/* generate the server key */
		satp_generate_server_key(skey, &mkey, keyid);

		/* generate a random device id */
		qsc_acp_generate(keyid + SATP_SID_SIZE, SATP_DID_SIZE);
		/* generate the device key */
		satp_generate_device_key(&dkey, skey, keyid);

		/* add the user id and passphrase to the database */
		qsc_memutils_copy(upass, dkey.kid, SATP_DID_SIZE);
		satp_server_passphrase_generate(upass + SATP_DID_SIZE, SATP_HASH_SIZE);
		server_print_passphrase(upass + SATP_DID_SIZE);

		/* hash the passphrase with scb before storing it */
		satp_server_passphrase_hash_generate((char*)upass + SATP_DID_SIZE, upass + SATP_DID_SIZE, SATP_HASH_SIZE);

		/* copy the user credential associated with this key to the database */
		server_create_path(fpath, SATP_USERDB_NAME);
		res = qsc_fileutils_copy_stream_to_file(fpath, upass, sizeof(upass));

		/* serialize the device key and save it to a file */
		server_create_path(fpath, SATP_DEVKEY_NAME);
		satp_serialize_device_key(sdkey, &dkey);
		res = qsc_fileutils_copy_stream_to_file(fpath, (char*)sdkey, sizeof(sdkey));

		/* clean up */
		qsc_memutils_clear(upass, sizeof(upass));
		qsc_memutils_clear(sdkey, sizeof(sdkey));
		qsc_memutils_clear(&dkey, sizeof(satp_device_key));

		if (res == true)
		{
			qsc_consoleutils_print_safe("server> The device-key has been saved to ");
			qsc_consoleutils_print_line(fpath);
			server_print_message("Distribute the device-key to the intended client.");

			/* store the server key */
			server_create_path(fpath, SATP_SRVKEY_NAME);
			satp_serialize_server_key(sskey, skey);
			res = qsc_fileutils_copy_stream_to_file(fpath, (char*)sskey, sizeof(sskey));

			/* clean up */
			qsc_memutils_clear(sskey, sizeof(sskey));

			if (res == true)
			{
				qsc_consoleutils_print_safe("server> The server-key has been saved to ");
				qsc_consoleutils_print_line(fpath);

				/* store the master key */
				server_create_path(fpath, SATP_MSTKEY_NAME);
				satp_serialize_master_key(smkey, &mkey);
				res = qsc_fileutils_copy_stream_to_file(fpath, (char*)smkey, sizeof(smkey));

				/* clean up */
				qsc_memutils_clear(smkey, sizeof(smkey));
				qsc_memutils_clear(&mkey, sizeof(satp_master_key));

				if (res == true)
				{
					qsc_consoleutils_print_safe("server> The master-key has been saved to ");
					qsc_consoleutils_print_line(fpath);
				}
				else
				{
					server_print_message("Could not save the master-key, aborting startup.");
				}
			}
			else
			{
				server_print_message("Could not save the server-key, aborting startup.");
			}
		}
		else
		{
			server_print_message("Could not save the device-key, aborting startup.");
		}
	}

	return res;
}

static void qsc_socket_exception_callback(const qsc_socket* source, qsc_socket_exceptions error)
{
	SATP_ASSERT(source != NULL);

	const char* emsg;

	if (source != NULL && error != qsc_socket_exception_success)
	{
		emsg = qsc_socket_error_to_string(error);
		server_print_message(emsg);
	}
}

static void server_send_echo(satp_connection_state* cns, const char* message, size_t msglen)
{
	/* This function can be modified to send data to a remote host.*/

	char mstr[SATP_CONNECTION_MTU] = "ECHO: ";
	char rstr[SATP_CONNECTION_MTU] = "RCVD #";
	uint8_t pmsg[SATP_CONNECTION_MTU] = { 0 };
	satp_network_packet pkt = { 0 };
	qsc_mutex mtx;
	size_t mlen;

	if (msglen > 0)
	{
		mlen = qsc_stringutils_string_size(rstr);
		qsc_stringutils_int_to_string((int)cns->target.connection, rstr + mlen, sizeof(rstr) - mlen);
		qsc_stringutils_concat_strings(rstr, sizeof(rstr), ": ");
		qsc_stringutils_concat_strings(rstr, sizeof(rstr), message);

		mtx = qsc_async_mutex_lock_ex();
		server_print_message(rstr);
		qsc_async_mutex_unlock_ex(mtx);

		mlen = qsc_stringutils_concat_strings(mstr, sizeof(mstr), message);
		pkt.pmessage = pmsg;
		satp_encrypt_packet(cns, (uint8_t*)mstr, mlen, &pkt);
		mlen = satp_packet_to_stream(&pkt, (uint8_t*)mstr);
		qsc_socket_send(&cns->target, (uint8_t*)mstr, mlen, qsc_socket_send_flag_none);
	}
}

static bool server_authentication_callback(satp_connection_state* cns, const uint8_t* message, size_t msglen)
{
	/* This emulates a passphrase hash lookup using the device id to fetch the 
	   client's passphrase hash stored on the server.
	   When the key is generated for a client, the server generates a 
	   passphrase, the user readable passphrase are the credential 
	   that is hashed with SCB, and the hash is stored in the server's database. 
	   The did is the client's unique id number, the server fetches the passphrase
	   hash associated with that did contained in its database. */

	uint8_t cred[SATP_HASH_SIZE] = { 0 };
	bool res;

	res = (msglen == SATP_DID_SIZE + SATP_HASH_SIZE);

	if (res == true)
	{
		const char* pcred;

		/* the did is the first half of the message,
		   the challenge passphrase is the second half of the message,
		   and the message itself is sent over an encrypted channel. */
		pcred = (char*)message + SATP_DID_SIZE;
		
		/* get the stored credential */
		server_fetch_user_credential(cred, message);
		/* verify hash with scb */
		res = satp_server_passphrase_hash_verify(cred, pcred, SATP_HASH_SIZE);

		if (res == true)
		{
			/* Authentication succeeded, grant server access to the client.
			   On failure the client is notified and disconnected automatically. */
			server_print_message("Authentication success! A client has logged on.");
		}
		else
		{
			server_print_message("Authentication failure! A client failed the logon challenge.");
		}
	}

	return res;
}

static void server_disconnect_callback(satp_connection_state* cns)
{
	qsc_mutex mtx;

	mtx = qsc_async_mutex_lock_ex();
	server_print_prompt();
	qsc_consoleutils_print_safe("The server has disconnected from host: ");
	qsc_consoleutils_print_line(cns->target.address);
	qsc_async_mutex_unlock_ex(mtx);
}

static void server_receive_callback(satp_connection_state* cns, const uint8_t* message, size_t msglen)
{
	/* Envelope data in an application header, in a request->response model.
	   Parse that header here, process requests from the client, and transmit the response. */

	server_send_echo(cns, (const char*)message, msglen);
}

int main(void)
{
	satp_server_key skey = { 0 };
	uint8_t kid[SATP_KID_SIZE] = { 0U };
	satp_errors err;

	server_print_banner();

	if (server_key_dialogue(&skey, kid) == true)
	{
		server_print_message("Waiting for a connection...");
		err = satp_server_start_ipv4(&skey, &server_receive_callback, &server_disconnect_callback, &server_authentication_callback);

		if (err != satp_error_none)
		{
			server_print_error(err);
			server_print_message("The network key-exchange failed, the application will exit.");
		}

		satp_server_quit();
	}
	else
	{
		server_print_message("The signature key-pair could not be created, the application will exit.");
	}

	server_print_message("Press any key to close...");
	qsc_consoleutils_get_wait();

	return 0;
}

