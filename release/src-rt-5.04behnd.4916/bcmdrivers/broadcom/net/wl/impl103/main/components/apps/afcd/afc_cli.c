/*
 * AFC Command Line Interface
 *
 * Copyright (C) 2024, Broadcom. All Rights Reserved.
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION
 * OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN
 * CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 *
 *
 * <<Broadcom-WL-IPTag/Dual:>>
 *
 * $Id: afc_cli.c 832722 2023-11-12 00:09:11Z $
 */

#include <getopt.h>

#include "afc_shared.h"
#include "afc_sock_util.h"
#include "afc.h"

#define AFC_MODULE	"CLI"

#define AFC_CLI_PRINT(fmt, arg...) AFC_PRINT("CLI: ", fmt, ##arg)

/* Processed command line arguments */
typedef struct afc_cmdargs {
	afc_cli_cmd_type_t cmd;
	uint32 msglevel;
} afc_cmdargs_t;

/* CLI command name and Command ID pair */
typedef struct afc_cli_cmd {
	char* cmd_name;
	afc_cli_cmd_type_t cmd_id;
} afc_cli_cmd_t;

/* All the CLI commands */
static afc_cli_cmd_t g_afc_cli_cmds[] = {
	{"msglevel",		AFC_CMD_CLI_MSGLEVEL},
	{"req",			AFC_CMD_CLI_SEND_REQ},
	{"stored",		AFC_CMD_CLI_STORED_RES},
};

/* Function to print the CLI usage */
static void
afc_usage()
{
	printf("usage: afc_cli <options> [ <value>]\n"
			"options are:\n"
			"	-c, --command	Command\n"
			"	-l, --level	Set Message Level\n"
			"	-h, --help	Help\n"
			"\n"
			"Commands are:\n"
			"	msglevel	Get Message Level\n"
			"	req		Send Available Spectrum Inquiry Request message\n"
			"	stored		Get Stored Available Spectrum Inquiry Response\n"
			"\n");
}

/* AFC CLI TCP Client connet, send and receive */
static int
afc_cli_send(afc_sock_data_t *in_sock_data)
{
	int ret = AFCE_OK, rcv_ret = 0;
	int sockfd = AFC_INVALID_SOCKET;
	afc_sock_data_t sock_data;
	afc_cli_cmd_general_resp_t *gen_resp;

	memset(&sock_data, 0, sizeof(sock_data));

	/* Connect to the server */
	sockfd = afc_connect_to_server(AFC_LOOPBACK_IP, EAPD_WKSP_AFC_TCP_CLI_PORT);
	if (sockfd == AFC_INVALID_SOCKET) {
		AFC_CLI_PRINT("Failed to connect to AFC Daemon\n");
		return AFCE_SOCKET;
	}

	/* Send the data */
	if (afc_socket_send_data(sockfd, in_sock_data) <= 0) {
		ret = -1;
		AFC_CLI_PRINT("Failed to send data to AFC Daemon\n");
		goto exit;
	}

	/* Get the response from the server */
	rcv_ret = afc_socket_recv_data(sockfd, &sock_data);
	if (rcv_ret <= 0) {
		ret = -1;
		AFC_CLI_PRINT("Failed to recieve data from AFC Daemon\n");
		goto exit;
	}

	gen_resp = (afc_cli_cmd_general_resp_t*)sock_data.data;
	gen_resp->resp_desc[sizeof(gen_resp->resp_desc) - 1] = '\0';
	gen_resp->resp_ctx[sizeof(gen_resp->resp_ctx) - 1] = '\0';
	AFC_CLI_PRINT("Description of Response from AFC Daemon: %d, %s\n%s",
			gen_resp->resp, gen_resp->resp_desc, gen_resp->resp_ctx);

exit:
	afc_close_socket(&sockfd);
	afc_free_sock_data(&sock_data);

	return ret;
}

/* Gets the CLI command ID from the command name */
afc_cli_cmd_type_t
afc_get_cli_command_id(const char *cmd)
{
	int i;
	afc_cli_cmd_type_t ret_id = -1;
	AFC_ENTER();

	for (i = 0; i < ARRAYSIZE(g_afc_cli_cmds); i++) {
		if (strcasecmp(cmd, g_afc_cli_cmds[i].cmd_name) == 0) {
			ret_id = g_afc_cli_cmds[i].cmd_id;
			goto end;
		}
	}

end:
	AFC_EXIT();
	return ret_id;
}

/* Parse the commandline parameters and populate the structure cmdarg with the command
 * and parameters if any
 */
static int
afc_cli_parse_opt(int argc, char *argv[], afc_cmdargs_t *cmdarg)
{
	int ret = AFCE_OK;
	int c, found = 0;

	memset(cmdarg, 0, sizeof(*cmdarg));
	cmdarg->cmd = -1;

	static struct option long_options[] = {
		{"command",	required_argument,	0, 'c'},
		{"level",	required_argument,	0, 'l'},
		{"help",	no_argument,		0, 'h'},
		{0,		0,			0, 0}

	};

	while (1) {
		int option_index = 0;
		c = getopt_long(argc, argv, "c:l:h", long_options, &option_index);
		if (c == -1) {
			if (found == 0) {
				afc_usage();
				exit(1);
			}
			goto end;
		}

		AFC_CLI_PRINT("c:'%c', optarg:%s\n", c, (optarg?optarg:"NULL"));
		found = 1;
		switch (c) {
			case 'c' :
				cmdarg->cmd = afc_get_cli_command_id(optarg);
				cmdarg->msglevel = -1;
				break;
			case 'l' :
				cmdarg->cmd = AFC_CMD_CLI_MSGLEVEL;
				cmdarg->msglevel = (uint32)strtoul(optarg, NULL, 0);
				break;

			default :
				afc_usage();
				exit(1);
		}
	}

end:
	return ret;
}

/* Validates the commands and its arguments */
static int
afc_cli_validate_cmdarg(afc_cmdargs_t *cmdarg)
{
	int ret = AFCE_OK;

	if (ret != AFCE_OK) {
		AFC_CLI_PRINT("Invalid Arguments to CLI. Error : %s\n", afcerrorstr(ret));
		afc_usage();
		exit(1);
	}

	return ret;
}

/* Prepare the CLI request from cmdarg */
static uint32
afc_cli_prepare_request_data(afc_cmdargs_t *cmdarg, afc_sock_data_t *sock_data)
{
	int ret = AFCE_OK;
	afc_cli_cmd_hdr_t *hdr;

	sock_data->data = (uint8*)afc_malloc(AFC_MAX_READ_BUFFER, &ret);
	AFC_ASSERT();

	hdr = (afc_cli_cmd_hdr_t*)sock_data->data;
	memset(hdr, 0, sizeof(*hdr));
	hdr->cmd = (uint8)cmdarg->cmd;
	hdr->ver = AFC_CLI_VERSION;

	if (cmdarg->cmd == AFC_CMD_CLI_MSGLEVEL) {
		afc_cli_cmd_msglevel_t *cmd;

		cmd = (afc_cli_cmd_msglevel_t*)sock_data->data;
		cmd->hdr.len = sizeof(*cmd);
		cmd->msglevel = cmdarg->msglevel;
		sock_data->len = cmd->hdr.len;
		AFC_CLI_PRINT("cmd MSGLEVEL %d\n", cmd->msglevel);
	} else if (cmdarg->cmd == AFC_CMD_CLI_SEND_REQ) {
		afc_cli_cmd_req_t *cmd;

		cmd = (afc_cli_cmd_req_t*)sock_data->data;
		cmd->hdr.len = sizeof(*cmd);
		sock_data->len = cmd->hdr.len;
		AFC_CLI_PRINT("cmd SEND_REQ\n");
	} else if (cmdarg->cmd == AFC_CMD_CLI_STORED_RES) {
		afc_cli_cmd_stored_res_t *cmd;

		cmd = (afc_cli_cmd_stored_res_t*)sock_data->data;
		cmd->hdr.len = sizeof(*cmd);
		sock_data->len = cmd->hdr.len;
		AFC_CLI_PRINT("cmd STORED_RES\n");
	}

end:
	return sock_data->len;
}

/* Process the command requested by the command-line */
static int
afc_cli_process(afc_cmdargs_t *cmdarg)
{
	int ret = AFCE_OK;
	afc_sock_data_t sock_data;

	memset(&sock_data, 0, sizeof(sock_data));

	if (cmdarg->cmd == -1) {
		afc_usage();
		exit(1);
	}

	/* Prepare the request */
	if (afc_cli_prepare_request_data(cmdarg, &sock_data) <= 0) {
		goto end;
	}

	/* Send and receive response */
	afc_cli_send(&sock_data);

end:
	afc_free_sock_data(&sock_data);

	return ret;
}

int
main(int argc, char **argv)
{
	int ret = AFCE_OK;
	afc_cmdargs_t cmdarg;

	ret = afc_cli_parse_opt(argc, argv, &cmdarg);
	AFC_ASSERT();

	ret = afc_cli_validate_cmdarg(&cmdarg);
	AFC_ASSERT();

	ret = afc_cli_process(&cmdarg);
	AFC_ASSERT();

end:
	return ret;
}
