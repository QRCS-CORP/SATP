#include "appclt.h"
#include "satp.h"
#include "client.h"
#include "async.h"
#include "consoleutils.h"
#include "fileutils.h"
#include "folderutils.h"
#include "memutils.h"
#include "sha3.h"
#include "socketclient.h"
#include "stringutils.h"

static void client_print_prompt(void)
{
	qsc_consoleutils_print_safe("client> ");
}

static void client_print_message(const char* message)
{
	size_t slen;

	if (message != NULL)
	{
		slen = qsc_stringutils_string_size(message);

		if (slen != 0)
		{
			qsc_consoleutils_print_safe("client> ");
			qsc_consoleutils_print_line(message);
		}
		else
		{
			qsc_consoleutils_print_safe("client> ");
		}
	}
}

static void client_print_string(const char* message, size_t msglen)
{
	if (message != NULL && msglen != 0)
	{
		qsc_consoleutils_print_line(message);
	}
}

static void client_print_error(satp_errors error)
{
	const char* msg;

	msg = satp_error_to_string(error);

	if (msg != NULL)
	{
		client_print_message(msg);
	}
}

static void client_print_banner(void)
{
	qsc_consoleutils_print_line("***********************************************************");
	qsc_consoleutils_print_line("* SATP: Symmetric Authenticated Tunneling Protocol Client *");
	qsc_consoleutils_print_line("*                                                         *");
	qsc_consoleutils_print_line("* Release:   v1.0.0.0a (A1)                               *");
	qsc_consoleutils_print_line("* Date:      March 14, 2025                               *");
	qsc_consoleutils_print_line("* Contact:   contact@qrcscorp.ca                          *");
	qsc_consoleutils_print_line("***********************************************************");
	qsc_consoleutils_print_line("");
}

static bool client_ipv4_dialogue(satp_device_key* ckey, qsc_ipinfo_ipv4_address* address, uint8_t* spass)
{
	uint8_t cskey[SATP_DKEY_ENCODED_SIZE];
	char fpath[QSC_FILEUTILS_MAX_PATH + 1U] = { 0 };
	char sadd[QSC_IPINFO_IPV4_STRNLEN + 1U] = { 0 };
	char cpass[SATP_HASH_SIZE + 2U] = { 0U };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	size_t slen;
	bool res;

	res = false;

	client_print_message("Enter the destination IPv4 address, ex. 192.168.1.1");
	client_print_prompt();
	slen = qsc_consoleutils_get_formatted_line(sadd, QSC_IPINFO_IPV4_STRNLEN);

	if (slen >= QSC_IPINFO_IPV4_MINLEN)
	{
		addv4t = qsc_ipinfo_ipv4_address_from_string(sadd);
		res = (qsc_ipinfo_ipv4_address_is_valid(&addv4t) == true &&
			qsc_ipinfo_ipv4_address_is_zeroed(&addv4t) == false);

		if (res == true)
		{
			qsc_memutils_copy(address->ipv4, addv4t.ipv4, QSC_IPINFO_IPV4_BYTELEN);
		}
		else
		{
			client_print_message("The address format is invalid.");
		}
	}
	else
	{
		client_print_message("The address format is invalid.");
	}

	if (res == true)
	{
		client_print_message("Enter the path of the device key:");
		client_print_prompt();
		slen = qsc_consoleutils_get_line(fpath, sizeof(fpath)) - 1;

		if (qsc_fileutils_exists(fpath) == true && 
			qsc_stringutils_string_contains(fpath, SATP_DEVKEY_EXT) == true)
		{
			/* copy the key from file to structure */
			qsc_fileutils_copy_file_to_stream(fpath, (char*)cskey, sizeof(cskey));
			satp_deserialize_device_key(ckey, cskey);

			/* Important: increment key index and erase current key */
			satp_increment_device_key(cskey);
			/* save the updated key to file */
			qsc_fileutils_copy_stream_to_file(fpath, (char*)cskey, sizeof(cskey));
			res = true;
		}
		else
		{
			res = false;
			client_print_message("The path is invalid or inaccessable.");
		}

		/* add the passphrase */
		client_print_message("Enter the login passphrase:");
		client_print_prompt();
		slen = qsc_consoleutils_get_line(cpass, sizeof(cpass)) - 1;
		res = (slen == SATP_HASH_SIZE);

		if (res == true)
		{
			qsc_memutils_copy(spass, cpass, slen);
			qsc_memutils_clear(cpass, sizeof(cpass));
		}
	}

	return res;
}

static void client_receive_callback(satp_connection_state* cns, const uint8_t* pmsg, size_t msglen)
{
	char* cmsg;

	cmsg = qsc_memutils_malloc(msglen + sizeof(char));

	if (cmsg != NULL)
	{
		qsc_memutils_clear(cmsg, msglen + sizeof(char));
		qsc_memutils_copy(cmsg, pmsg, msglen);
		client_print_string(cmsg, msglen);
		client_print_prompt();
		qsc_memutils_alloc_free(cmsg);
	}
}

static void client_send_loop(satp_connection_state* cns)
{
	satp_network_packet pkt = { 0 };
	uint8_t pmsg[SATP_CONNECTION_MTU] = { 0 };
	uint8_t msgstr[SATP_CONNECTION_MTU] = { 0 };
	char sin[SATP_CONNECTION_MTU + 1] = { 0 };
	size_t mlen;

	mlen = 0;

	/* client authentication challenge */


	/* start the sender loop */
	while (true)
	{
		client_print_prompt();

		if (qsc_consoleutils_line_contains(sin, "satp quit"))
		{
			satp_connection_close(cns, satp_error_none, true);
			break;
		}
		else
		{
			if (mlen > 0)
			{
				/* convert the packet to bytes */
				pkt.pmessage = pmsg;
				satp_encrypt_packet(cns, (const uint8_t*)sin, mlen, &pkt);
				qsc_memutils_clear((uint8_t*)sin, sizeof(sin));
				mlen = satp_packet_to_stream(&pkt, msgstr);
				qsc_socket_send(&cns->target, msgstr, mlen, qsc_socket_send_flag_none);
			}
		}

		mlen = qsc_consoleutils_get_line(sin, sizeof(sin)) - 1;

		if (mlen > 0 && (sin[0] == '\n' || sin[0] == '\r'))
		{
			client_print_message("");
			mlen = 0;
		}
	}
}

static void qsc_socket_exception_callback(const qsc_socket* source, qsc_socket_exceptions error)
{
	SATP_ASSERT(source != NULL);

	const char* emsg;

	if (source != NULL && error != qsc_socket_exception_success)
	{
		emsg = qsc_socket_error_to_string(error);
		client_print_message(emsg);
	}
}

int main(void)
{
	satp_device_key ckey = { 0 };
	qsc_ipinfo_ipv4_address addv4t = { 0 };
	uint8_t spass[SATP_HASH_SIZE] = { 0U };
	size_t ectr;
	bool res;

	res = false;
	ectr = 0;
	client_print_banner();

	while (ectr < 3)
	{
		res = client_ipv4_dialogue(&ckey, &addv4t, spass);
		ckey.spass = spass;

		if (res == true)
		{
			break;
		}

		++ectr;
	}

	if (res == true)
	{
		satp_client_connect_ipv4(&ckey, &addv4t, SATP_SERVER_PORT, &client_send_loop, &client_receive_callback);
	}
	else
	{
		qsc_consoleutils_print_line("Invalid input, exiting the application.");
	}

	client_print_message("The application has exited. Press any key to close..");
	qsc_consoleutils_get_wait();

	return 0;
}
