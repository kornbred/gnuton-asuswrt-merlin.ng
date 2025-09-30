/*
 * AFC socket utility for both client and server (Linux)
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
 * $Id: afc_sock_util.h 832722 2023-11-12 00:09:11Z $
 */

#ifndef _AFC_SOCK_UTIL_H_
#define _AFC_SOCK_UTIL_H_

#include <net/if.h>
#include <arpa/inet.h>
#include <typedefs.h>
#include <bcmutils.h>
#include <sys/socket.h>
#include <unistd.h>
#include "security_ipc.h"

#define AFC_INVALID_SOCKET		-1
#define AFC_MAX_READ_BUFFER		1448
/* This version is used in wbd2/slave/wbd_slave_com_hdlr.c file for forwarding AFC request from
 * repeater to AFC daemon. So, change there as well if it is changed here
 */
#define AFC_CLI_VERSION			1
#define AFC_MAX_CLI_RESP_DESC		64
#define AFC_MAX_CLI_RESP_CTX		256
#define AFC_MAC_ADDR_LEN		6

#define AFC_SLEEP_SERVER_FAIL		5 /* Interval between each server creation if fails */

/* Loopback IP address */
#define AFC_LOOPBACK_IP			"127.0.0.1"

#define AFC_TM_SOCKET			30	/* Timeout for Socket's read and write */

/* Command ID's
 * Before modifying this command ID numbering check the WBD source code(wbd_slave_com_hdlr.c)
 * AFC_CMD_CLI_PASS_REQ is used there hardcoded as 3.
 */
typedef enum afc_cli_cmd_type {
	AFC_CMD_CLI_MSGLEVEL,	/* Set message level */
	AFC_CMD_CLI_SEND_REQ,	/* Send Available Spectrum Inquiry Request message */
	AFC_CMD_CLI_STORED_RES,	/* Get Stored Available Spectrum Inquiry Response */
	AFC_CMD_CLI_PASS_REQ = 3,	/* Pass the Available Spectrum Inquiry Request from WBD to
					 * AFC server
					 */
	AFC_CMD_CLI_PASS_RESP = 4	/* Pass the received Spectrum Inquiry Response from RootAP
					 * to AFCD.
					 */
} afc_cli_cmd_type_t;

/* Command header */
typedef struct afc_cli_cmd_hdr {
	uint16 ver;	/* Version of CLI */
	uint8 cmd;	/* Command ID */
	uint32 len;	/* Length of the whole data including header */
} __attribute__ ((__packed__)) afc_cli_cmd_hdr_t;

/* Set message level command */
typedef struct afc_cli_cmd_msglevel {
	afc_cli_cmd_hdr_t hdr;	/* Header */
	uint32 msglevel;	/* Message level to be set */
} __attribute__ ((__packed__)) afc_cli_cmd_msglevel_t;

/* General response for a command if there is no specific response */
typedef struct afc_cli_cmd_general_resp {
	afc_cli_cmd_hdr_t hdr;			/* Header */
	int resp;				/* Response code of type AFCE_XXX */
	char resp_desc[AFC_MAX_CLI_RESP_DESC];	/* Short description which got from
						 * afcerrorstr function
						 */
	char resp_ctx[AFC_MAX_CLI_RESP_CTX];	/* response specific context to print */
} __attribute__ ((__packed__)) afc_cli_cmd_general_resp_t;

/* Send Available Spectrum Inquiry Request message command */
typedef struct afc_cli_cmd_req {
	afc_cli_cmd_hdr_t hdr;	/* Header */
} __attribute__ ((__packed__)) afc_cli_cmd_req_t;

/* Get Stored Available Spectrum Inquiry Response command */
typedef struct afc_cli_cmd_stored_res {
	afc_cli_cmd_hdr_t hdr;	/* Header */
} __attribute__ ((__packed__)) afc_cli_cmd_stored_res_t;

/* Pass the Available Spectrum Inquiry Request from WBD to AFC server */
typedef struct afc_cli_cmd_pass_req {
	afc_cli_cmd_hdr_t hdr;		/* Header */
	uint8 al_mac[AFC_MAC_ADDR_LEN];	/* MAC address from where request came */
	char *req;			/* Available Spectrum Inquiry Request in JSON format */
} __attribute__ ((__packed__)) afc_cli_cmd_pass_req_t;

/* Data from socket */
typedef struct afc_sock_data {
	uint32 len;	/* Length of the data */
	uint8 *data;	/* Data */
} afc_sock_data_t;

/* Free the socket data */
void afc_free_sock_data(afc_sock_data_t *sock_data);

/* Closes the socket */
void afc_close_socket(int *sockfd);

/* Connects to the server given the IP address and port number */
int afc_connect_to_server(char *straddrs, unsigned int nport);

/* Sends the data to socket */
unsigned int afc_socket_send_data(int sockfd, afc_sock_data_t *sock_data);

/* Receive all the data. caller should free the memory using afc_free_sock_data */
int afc_socket_recv_data(int sockfd, afc_sock_data_t *sock_data);

/* Open a TCP socket for getting requests from client */
int afc_open_server_fd(int portno);

/* Accept the connection from the client */
int afc_accept_connection(int server_fd);

/* Read "length" bytes of "data" from non-blocking socket */
unsigned int afc_sock_recvdata(int sockfd, unsigned char *data,
	unsigned int length);

/* to recieve data till the null character. caller should free the memory */
unsigned int afc_wbd_socket_recv_data(int sockfd, char **data);

/* Try to open the server FD's till it succeeds */
int afc_try_open_server_fd(int portno, int* error);

/* Try to connect to locpold server FD */
int afc_try_to_get_locpold_fd();
#endif /* _AFC_SOCK_UTIL_H_ */
