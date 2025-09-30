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
 * $Id: afc_sock_util.c 832722 2023-11-12 00:09:11Z $
 */
#include <fcntl.h>
#include <errno.h>
#include <limits.h>
#include <sys/un.h>
#include "afc_shared.h"
#include "afc_sock_util.h"
#include "afc.h"
#include <locpol_keys.h>

#define AFC_MODULE	"SOCK"

#define AFC_LOCPOLD_MAX_CONNECT_RETRIES	4	/* Number of retries within afc_req_locpold */
#define AFC_LOCPOLD_RETRY_GAP		20	/* Retry gap (in secs) within afc_req_locpold */

/* Free the socket data */
void
afc_free_sock_data(afc_sock_data_t *sock_data)
{
	if (sock_data == NULL) {
		return;
	}

	if (sock_data->data) {
		free(sock_data->data);
		sock_data->data = NULL;
	}

	sock_data->len = 0;
}

/* Closes the socket */
void
afc_close_socket(int *sockfd)
{
	if (*sockfd == AFC_INVALID_SOCKET)
		return;

	close(*sockfd);
	*sockfd = AFC_INVALID_SOCKET;
}

/* Connects to the server given the IP address and port number */
int
afc_connect_to_server(char* straddrs, unsigned int nport)
{
	struct sockaddr_in server_addr;
	int res, valopt;
	long arg;
	fd_set readfds;
	struct timeval tv;
	socklen_t lon;
	int sockfd;
	AFC_ENTER();

	sockfd = AFC_INVALID_SOCKET;
	memset(&server_addr, 0, sizeof(server_addr));

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		AFC_ERROR("Socket call failed for ip[%s] port[%d]. Error[%s]\n", straddrs,
			nport, strerror(errno));
		goto error;
	}

	/* Set nonblock on the socket so we can timeout */
	if ((arg = fcntl(sockfd, F_GETFL, NULL)) < 0 ||
		fcntl(sockfd, F_SETFL, arg | O_NONBLOCK) < 0) {
			AFC_ERROR("fcntl call failed for ip[%s] port[%d]. Error[%s]\n",
				straddrs, nport, strerror(errno));
			goto error;
	}
	server_addr.sin_family = AF_INET;
	server_addr.sin_port = htons(nport);
	server_addr.sin_addr.s_addr = inet_addr(straddrs);

	res = connect(sockfd, (struct sockaddr*)&server_addr, sizeof(struct sockaddr));
	if (res < 0) {
		if (errno == EINPROGRESS) {
			tv.tv_sec = AFC_TM_SOCKET;
			tv.tv_usec = 0;
			FD_ZERO(&readfds);
			FD_SET(sockfd, &readfds);
			if (select(sockfd+1, NULL, &readfds, NULL, &tv) > 0) {
				lon = sizeof(int);
				getsockopt(sockfd, SOL_SOCKET, SO_ERROR,
					(void*)(&valopt), &lon);
				if (valopt) {
					AFC_ERROR("getsockopt call failed for ip[%s] port[%d]. "
						"valopt[%d]. Error[%s]\n", straddrs, nport,
						valopt, strerror(valopt));
					goto error;
				}
			} else {
				AFC_ERROR("Select timeout/error for ip[%s] port[%d]. Error[%s]\n",
					straddrs, nport, strerror(errno));
				goto error;
			}
		} else {
			AFC_ERROR("Connect failed For ip[%s] port[%d]. Error[%s]\n",
				straddrs, nport, strerror(errno));
			goto error;
		}
	}
	AFC_DEBUG("Connected to ip[%s] and Port[%d] Successfully. sockfd[%d]\n",
		straddrs, nport, sockfd);

	AFC_EXIT();
	return sockfd;

	/* Error Handling */
error:
	if (sockfd != AFC_INVALID_SOCKET)
		afc_close_socket(&sockfd);
	AFC_EXIT();
	return AFC_INVALID_SOCKET;
}

/* Sends the data to socket */
unsigned int
afc_socket_send_data(int sockfd, afc_sock_data_t *sock_data)
{
	int ret = 0, nret = 0;
	unsigned int rem = sock_data->len, totalsent = 0;
	AFC_ENTER();

	AFC_DEBUG("Send data of %u bytes on sockfd[%d]\n", sock_data->len, sockfd);

	/* Loop till all the data sent */
	while (totalsent < sock_data->len) {
		fd_set WriteFDs;
		struct timeval tv;

		FD_ZERO(&WriteFDs);

		if (sockfd == AFC_INVALID_SOCKET) {
			AFC_ERROR("Invalid socket. sockfd[%d]\n", sockfd);
			goto error;
		}

		FD_SET(sockfd, &WriteFDs);

		tv.tv_sec = AFC_TM_SOCKET;
		tv.tv_usec = 0;
		if ((ret = select(sockfd+1, NULL, &WriteFDs, NULL, &tv)) > 0) {
			if (FD_ISSET(sockfd, &WriteFDs)) {
				;
			} else {
				AFC_ERROR("Exception occured on sockfd[%d]\n", sockfd);
				goto error;
			}
		} else {
			if (ret == 0) {
				AFC_WARNING("Select timeout after %d sec on sockfd[%d]\n",
						AFC_TM_SOCKET, sockfd);
			} else {
				AFC_ERROR("Send error [%s] on sockfd[%d]\n",
					strerror(errno), sockfd);
			}
			goto error;
		}

		nret = send(sockfd, &(sock_data->data[totalsent]), rem, 0);
		if (nret < 0) {
			AFC_ERROR("Send failed. Error: %s. %u bytes remained to send on "
				"sockfd[%d]\n", strerror(errno), rem, sockfd);
			goto error;
		}
		totalsent += nret;
		rem -= nret;
		nret = 0;
	}

	AFC_DEBUG("Sent Total %u bytes out of %u bytes on sockfd[%d]\n",
		totalsent, sock_data->len, sockfd);
	AFC_EXIT();
	return totalsent;
error:
	AFC_EXIT();
	return 0;
}

/* Read "length" bytes of "data" from non-blocking socket */
static unsigned int
afc_sock_recv(int sockfd, uint8 *data, uint32 length)
{
	int ret = 0;
	unsigned int nbytes, totalread = 0;
	struct timeval tv;
	fd_set ReadFDs, ExceptFDs;

	/* Keep on Reading, untill Total Read Bytes is less than length */
	while (totalread < length) {

		FD_ZERO(&ReadFDs);
		FD_ZERO(&ExceptFDs);
		FD_SET(sockfd, &ReadFDs);
		FD_SET(sockfd, &ExceptFDs);
		tv.tv_sec = AFC_TM_SOCKET;
		tv.tv_usec = 0;

		if ((ret = select(sockfd + 1, &ReadFDs, NULL, &ExceptFDs, &tv)) > 0) {
			if (!FD_ISSET(sockfd, &ReadFDs)) {
				AFC_ERROR("Exception occured on sockfd[%d]\n", sockfd);
				goto error;
			}
		} else {

			if (ret == 0) {
				AFC_WARNING("Select timeout after %d sec on sockfd[%d]\n",
						AFC_TM_SOCKET, sockfd);
			} else {
				AFC_ERROR("Read error [%s] on sockfd[%d]\n",
					strerror(errno), sockfd);
			}
			goto error;

		}

		nbytes = read(sockfd, &(data[totalread]), (length - totalread));

		if (nbytes <= 0) {
			AFC_ERROR("Read error [%s] on sockfd[%d] nbytes=%d\n", strerror(errno),
					sockfd, nbytes);
			goto error;
		}

		totalread += nbytes;
	}
	AFC_DEBUG("Received %u bytes on sockfd[%d]\n", totalread, sockfd);

	return totalread;

error:
	return 0;
}

/* Receive all the data. caller should free the memory using afc_free_sock_data */
int
afc_socket_recv_data(int sockfd, afc_sock_data_t *sock_data)
{
	unsigned int nbytes, totalread = 0;
	afc_cli_cmd_hdr_t cmd_hdr;
	int ret = AFCE_OK;
	AFC_ENTER();

	/* First read only header. From header we will be knowing the total buffer size */
	memset(&cmd_hdr, 0, sizeof(cmd_hdr));
	nbytes = afc_sock_recv(sockfd, (void*)&cmd_hdr, sizeof(cmd_hdr));
	if (nbytes < sizeof(cmd_hdr)) {
		AFC_ERROR("Doesn't contain enough data. Only %u bytes available on sockfd[%d]\n",
			nbytes, sockfd);
		goto end;
	}

	if (cmd_hdr.len > USHRT_MAX) {
		AFC_ERROR("Length specified in header %u exceeds maximum expected size %u on "
			"sockfd[%d]\n",
			cmd_hdr.len, USHRT_MAX, sockfd);
		goto end;
	}

	AFC_INFO("Received data version[%d] Command[%d] Len[%u] on sockfd[%d]\n",
		cmd_hdr.ver, cmd_hdr.cmd, cmd_hdr.len, sockfd);
	/* Include 1 byte for NULL termination */
	sock_data->data = (uint8*)afc_malloc((cmd_hdr.len + 1), &ret);
	AFC_ASSERT();

	memcpy(sock_data->data, &cmd_hdr, sizeof(cmd_hdr));
	sock_data->len = cmd_hdr.len;
	totalread = sizeof(cmd_hdr);

	/* If the read is still pending */
	if (cmd_hdr.len > totalread) {
		totalread += afc_sock_recv(sockfd, sock_data->data+totalread,
			(sock_data->len - totalread));
	}

	AFC_DEBUG("Read %u bytes on sockfd[%d]\n", totalread, sockfd);
	AFC_EXIT();
	return totalread;

end:
	if (sock_data->data) {
		free(sock_data->data);
		sock_data->data = NULL;
	}
	AFC_EXIT();
	return AFC_INVALID_SOCKET;
}

/* to recieve data till the null character. caller should free the memory */
unsigned int
afc_wbd_socket_recv_data(int sockfd, char **data)
{
	unsigned int nbytes, totalread = 0, cursize = 0;
	struct timeval tv;
	fd_set ReadFDs, ExceptFDs;
	char *buffer = NULL;
	int ret = 0;
	AFC_ENTER();

	/* Read till the null character or error */
	while (1) {
		FD_ZERO(&ReadFDs);
		FD_ZERO(&ExceptFDs);
		FD_SET(sockfd, &ReadFDs);
		FD_SET(sockfd, &ExceptFDs);
		tv.tv_sec = AFC_TM_SOCKET;
		tv.tv_usec = 0;

		/* Allocate memory for the buffer */
		if (totalread >= cursize) {
			char *tmp;

			cursize += AFC_MAX_READ_BUFFER;
			tmp = (char*)realloc(buffer, cursize);
			if (tmp == NULL) {
				AFC_ERROR("Failed to allocate memory for read. sockfd=%d.\n",
					sockfd);
				goto error;
			}
			buffer = tmp;
		}
		if ((ret = select(sockfd+1, &ReadFDs, NULL, &ExceptFDs, &tv)) > 0) {
			if (FD_ISSET(sockfd, &ReadFDs)) {
				/* fprintf(stdout, "SOCKET : Data is ready to read\n"); */;
			} else {
				AFC_ERROR("Exception occured. sockfd=%d\n", sockfd);
				goto error;
			}
		} else {
			if (ret == 0) {
				AFC_WARNING("Select timeout after %d sec. sockfd=%d\n",
					AFC_TM_SOCKET, sockfd);
			} else {
				AFC_ERROR("Recv error [%s]. sockfd=%d\n", strerror(errno), sockfd);
			}
			goto error;
		}

		nbytes = read(sockfd, buffer+totalread, (cursize - totalread));
		totalread += nbytes;

		if (nbytes <= 0) {
			AFC_ERROR("Read error [%s]. sockfd=%d nbytes=%u\n", strerror(errno),
				sockfd, nbytes);
			goto error;
		}

		/* Check the last byte for NULL termination */
		if (buffer[totalread-1] == '\0') {
			break;
		}
	}

	*data = buffer;

	AFC_DEBUG("Read %u bytes. sockfd=%d\n", totalread, sockfd);
	AFC_EXIT();
	return totalread;

error:
	if (buffer)
		free(buffer);
	AFC_EXIT();
	return 0;
}

/* Open a TCP socket for getting requests from client */
int
afc_open_server_fd(int portno)
{
	int sockfd = AFC_INVALID_SOCKET, optval = 1;
	struct sockaddr_in sockaddr;

	memset(&sockaddr, 0, sizeof(sockaddr));
	sockaddr.sin_family = AF_INET;
	sockaddr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
	sockaddr.sin_port = htons(portno);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		AFC_ERROR("Socket call failed for port[%d]. Error[%s]\n", portno, strerror(errno));
		goto error;
	}

	if (fcntl(sockfd, F_SETFD, FD_CLOEXEC) == -1) {
		AFC_ERROR("Unable to set fd close on exec on sockfd[%d]. Error[%s]\n",
			sockfd, strerror(errno));
		goto error;
	}

	if (setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) < 0) {
		AFC_ERROR("Unable to setsockopt. portno=%d. sockfd=%d. Error[%s]\n", portno,
				sockfd, strerror(errno));
		goto error;
	}

	if (bind(sockfd, (struct sockaddr *) &sockaddr, sizeof(sockaddr)) < 0) {
		AFC_ERROR("Unable to bind to socket. portno=%d sockfd=%d Error[%s]\n", portno,
				sockfd, strerror(errno));
		goto error;
	}

	if (listen(sockfd, 10) < 0) {
		AFC_ERROR("Socket listen error. portno=%d sockfd=%d Error[%s]\n", portno, sockfd,
			strerror(errno));
		goto error;
	}

	AFC_DEBUG("Opened listen socket: %d\n", sockfd);
	return sockfd;

error:
	if (sockfd != AFC_INVALID_SOCKET)
		afc_close_socket(&sockfd);

	return AFC_INVALID_SOCKET;
}

/* Accept the connection from the client */
int
afc_accept_connection(int server_fd)
{
	int childfd = AFC_INVALID_SOCKET;
	socklen_t clientlen;
	struct sockaddr_in clientaddr;

	clientlen = sizeof(clientaddr);
	childfd = accept(server_fd, (struct sockaddr *)&clientaddr, &clientlen);
	if (childfd < 0) {
		AFC_ERROR("Client accept error [%s]. server_fd=%d childfd=%d\n", strerror(errno),
				server_fd, childfd);
		return AFC_INVALID_SOCKET;
	}

	AFC_DEBUG("Opened childfd %d for incoming request on server_fd[%d]\n", childfd, server_fd);
	return childfd;
}

/* Try to open the server FD's till it succeeds */
int
afc_try_open_server_fd(int portno, int* error)
{
	int sfd = AFC_INVALID_SOCKET;
	AFC_ENTER();

	while (1) {
		sfd = afc_open_server_fd(portno);
		if (sfd == AFC_INVALID_SOCKET) {
			AFC_DEBUG("Failed to Open Server Port : %d. Wait for %d seconds and "
				"retry\n", portno, AFC_SLEEP_SERVER_FAIL);
			sleep(AFC_SLEEP_SERVER_FAIL);
			continue;
		}
		break;
	}
	AFC_INFO("Successfully Opened Server Socket: %d on Port: %d\n", sfd, portno);

	if (error != NULL) {
		if (sfd == AFC_INVALID_SOCKET) {
			*error = AFCE_SOCKET;
		} else {
			*error = AFCE_OK;
		}
	}

	AFC_EXIT();
	return sfd;
}

/* Try to open unix domain socket with locapold */
int
afc_try_to_get_locpold_fd()
{
	int fd, connect_count = 0;
	struct sockaddr_un addr;
	int flags;

	AFC_ENTER();

	fd = socket(AF_UNIX, SOCK_SEQPACKET, 0);
	if (fd == AFC_INVALID_SOCKET) {
		AFC_ERROR("Could not make socket, %s\n", strerror(errno));
		goto error;
	}
	addr.sun_family = AF_UNIX;
	AFCSTRNCPY(addr.sun_path, afc_nvram_safe_get(key_lp_cmd_path),
		sizeof(addr.sun_path));

	/* connect to locpold unix socket, retry AFC_LOCPOLD_MAX_CONNECT_RETRIES times with
	 * AFC_LOCPOLD_RETRY_GAP secs gap.
	 */
	while (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) == -1) {
		if (connect_count++ > AFC_LOCPOLD_MAX_CONNECT_RETRIES) {
			AFC_ERROR("Could not connect to locpold, %s\n", strerror(errno));
			close(fd);
			goto error;
		}
		AFC_INFO("Could not connect to locpold, %s\n", strerror(errno));
		sleep(AFC_LOCPOLD_RETRY_GAP);
	}

	flags = fcntl(fd, F_GETFL);
	if (flags >= 0) {
		flags |= O_NONBLOCK;
		if (fcntl(fd, F_SETFL, flags) < 0) {
			AFC_INFO("Failed to set O_NONBLOCK on fd(%d) \n", fd);
		}
	}

	AFC_EXIT();
	return fd;

error:
	AFC_EXIT();
	return AFC_INVALID_SOCKET;
}
