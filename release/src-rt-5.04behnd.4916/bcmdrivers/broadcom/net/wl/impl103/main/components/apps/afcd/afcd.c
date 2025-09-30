/*
 * AFC Daemon
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
 * $Id: afcd.c 832722 2023-11-12 00:09:11Z $
 */

#define TYPEDEF_FLOAT_T
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <signal.h>
#include <errno.h>
#include <bcmnvram.h>
#include <sys/un.h>
#include <syslog.h>

#include "common_utils.h"
#include "shutils.h"
#include <wlif_utils.h>

#include "afcd.h"
#include "afc_shared.h"
#include "afc_sock_util.h"
#include <locpol_ipc_cmn.h>
#include <locpol_ipc_ad.h>
#define AFC_MODULE	"Daemon"

/* Timeout to check the date sync timer */
#define AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT	300u	/* 300 seconds */
#define AFC_DEFAULT_SP_GAIN_CHECK_TIMEOUT	30u	/* 30 seconds */
/* Number of times the timer should repeat to check the date sync */
#define AFC_DEFAULT_NTP_DATE_CHECK_MAX_COUNT	5u

#define AFC_LOCPOLD_MAX_SEQ_OFF			4 /* Acceptable seq_no offset b/w req and resp */
#define AFC_DEFAULT_MIN_DESIRED_EIRP		24	/* Default desired EIRP in units of dBm */

afcd_info_t *g_afcdinfo = NULL;

/* Create timer to perform Available Spectrum Inquiry Request once expired */
static void afcd_create_inquiry_request_timer(afcd_info_t *info, bool last_web_req_status);
/* Add timers to micro scheduler */
static int afcd_add_timers(bcm_usched_handle *hdl, void *arg, unsigned long long timeout,
	bcm_usched_timerscbfn *cbfn, int repeat_flag);
/* Create timer to check NTP date update */
static void afcd_create_check_date_sync_timer(afcd_info_t *info);
/* Process spectrum inquiry request which had the location data */
static int afcd_process_spec_inq_req(avl_spec_inq_req_t *spec_inq_req);
/* Create timer to check for the sp gain after configuring the wl with afc response */
static int afcd_create_sp_gain_check_timer(afcd_info_t *info);
/* Updates location req msg flags and performs actions based on afcd state */
static void afcd_next_action_on_state_change(afcd_info_t *info);
/* Remove a file descriptor from the scheduler */
static int afcd_remove_fd(bcm_usched_handle *hdl, int fd);

/* Get AFC module info */
afcd_info_t *
afcd_get_ginfo()
{
	return (g_afcdinfo);
}

/* Update the gap enforced between web requests based on previous web-request's status.
 * Reset to minimum configured value on success, double up to maximum on error.
 */
static void
afcd_update_web_req_gap(afcd_info_t *info, bool last_web_req_status)
{
	uint32 nv_min_req_gap, nv_max_req_gap;
	AFC_ENTER();

	nv_min_req_gap = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_MIN_REQ_GAP,
		AFC_DEF_MIN_REQ_GAP);

	// reset the request gap on success
	if (last_web_req_status) {
		info->web_req_gap = nv_min_req_gap;
		return;
	}

	nv_max_req_gap = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_MAX_REQ_GAP,
		AFC_DEF_MAX_REQ_GAP);

	if (nv_max_req_gap < nv_min_req_gap) {
		nv_max_req_gap = nv_min_req_gap;
	}

	// double the request gap on error
	if ((info->web_req_gap * 2) <= nv_max_req_gap) {
		info->web_req_gap *= 2;
	}

	AFC_EXIT();
}

/* AFC to WBD, send and receive */
static int
afc_to_wbd_send(afc_sock_data_t *in_sock_data)
{
	int ret = AFCE_OK, sockfd = AFC_INVALID_SOCKET;
	unsigned int rcv_ret = 0;
	char *read_buf = NULL;

	/* Connect to the server */
	sockfd = afc_connect_to_server(AFC_LOOPBACK_IP, EAPD_WKSP_WBD_TCP_SLAVECLI_PORT);
	if (sockfd == AFC_INVALID_SOCKET) {
		AFC_ERROR("Failed to connect to WBD Slave Daemon\n");
		return AFCE_SOCKET;
	}

	/* Send the data */
	if (afc_socket_send_data(sockfd, in_sock_data) <= 0) {
		ret = -1;
		AFC_ERROR("Failed to send data to WBD Slave Daemon\n");
		goto exit;
	}

	/* Get the response from the server */
	rcv_ret = afc_wbd_socket_recv_data(sockfd, &read_buf);
	if ((rcv_ret == 0) || (read_buf == NULL)) {
		ret = -1;
		AFC_ERROR("No data to read sockfd[%d]\n", sockfd);
		goto exit;
	}

	AFC_DEBUG("Response from WBD(Len %u):%s\n", rcv_ret, read_buf);

exit:
	afc_close_socket(&sockfd);
	if (read_buf) {
		free(read_buf);
	}

	return ret;
}

/* Read the Available Spectrum Inquiry Request, Create JSON data and send it to WBD slave */
static int
afcd_send_available_spectrum_inquiry_req_to_wbd(afcd_info_t *info)
{
	int ret = AFCE_OK;
	char *json_data = NULL, *wbd_jason_data = NULL;
	afc_sock_data_t sock_data;
	AFC_ENTER();

	memset(&sock_data, 0, sizeof(sock_data));

	/* Create JSON data from request */
	json_data = (char*)afc_json_data_from_request(&g_afcdinfo->spec_inq_req_msg);
	if (!json_data) {
		goto end;
	}
	AFC_DEBUG("JSON Input to AFC System: Len %zu \n%s\n", strlen(json_data), json_data);

	afc_write_to_file(REQUEST_JSON_FILENAME, json_data, strlen(json_data)); // Log json request

	wbd_jason_data = afc_json_wbd_data_from_request(json_data);
	if (!wbd_jason_data) {
		goto end;
	}

	sock_data.len = strlen(wbd_jason_data);
	sock_data.data = (uint8*)afc_malloc((sock_data.len + 1), &ret);
	if (!sock_data.data) {
		AFC_ERROR("Failed to allocate memory\n");
		goto end;
	}

	memcpy(sock_data.data, wbd_jason_data, sock_data.len);
	/* Include NULL as the WBD CLI expects NULL character in the end becuase it is a
	 * JSON string
	 */
	sock_data.len++;
	AFC_DEBUG("JSON Input to WBD System: Len %u \n%s\n", sock_data.len, sock_data.data);
	ret = afc_to_wbd_send(&sock_data);

end:
	/* Free the json data created from request */
	if (json_data) {
		free(json_data);
	}
	if (wbd_jason_data) {
		free(wbd_jason_data);
	}
	afc_free_sock_data(&sock_data);
	AFC_EXIT();
	return ret;
}

/* Read the Available Spectrum Inquiry Request, Create JSON data, POST Available Spectrum
 * Inquiry Request and parse the JSON response
 */
static int
afcd_perform_available_spectrum_inquiry_req(afcd_info_t *info)
{
	int ret = AFCE_OK;
	AFC_ENTER();

	if (info->mode == AFCD_MODE_PROXY) {
		afcd_send_available_spectrum_inquiry_req_to_wbd(g_afcdinfo);
	} else {
		/* Create JSON data, POST Available Spectrum Inquiry Request and
		 * parse the JSON response
		 */
		ret = afc_perform_available_spectrum_inquiry_req(&g_afcdinfo->spec_inq_req_msg,
			&g_afcdinfo->spec_inq_resp_msg);

		if (ret == AFCE_OK) {
			afc_dump_available_spectrum_inquiry_response(&info->spec_inq_resp_msg);
			ret = afc_consume_available_spectrum_inquiry_response(
					&info->spec_inq_resp_msg);
		}
	}

	/* Create a timer to check for sp gain and if not satisfied than set use cached to 0 */
	if (ret == AFCE_OK && g_afcdinfo->spec_inq_resp_msg.spec_inq_resp.count > 0) {
		afcd_create_sp_gain_check_timer(g_afcdinfo);
	}

	/* Create timer to perform the next Available Spectrum Inquiry Request */
	afcd_create_inquiry_request_timer(g_afcdinfo, (ret == AFCE_OK));

	AFC_EXIT();
	return ret;
}

/* Process set message level CLI command */
static void
afcd_process_msglevel_cli_cmd(afc_cli_cmd_msglevel_t *cmd_msglevel, int childfd)
{
	int ret = AFCE_OK;
	afc_cli_cmd_general_resp_t gen_resp;
	afc_sock_data_t sock_data;
	AFC_ENTER();

	if (cmd_msglevel->msglevel != UINT_MAX) {
		afc_set_msglevel(cmd_msglevel->msglevel);
		AFC_PRINT("AFCD-CLI: ", "Set message level to %u successful\n", g_afc_msglevel);
	}

	memset(&gen_resp, 0, sizeof(gen_resp));

	memcpy(&gen_resp.hdr, &cmd_msglevel->hdr, sizeof(gen_resp.hdr));
	gen_resp.resp = ret;
	AFC_SNPRINTF(gen_resp.resp_desc, sizeof(gen_resp.resp_desc), "%s", afcerrorstr(ret));
	AFC_SNPRINTF(gen_resp.resp_ctx, sizeof(gen_resp.resp_ctx), "msglevel is %u/0x%04X\n",
			g_afc_msglevel, g_afc_msglevel);
	gen_resp.hdr.len = sizeof(gen_resp);

	sock_data.data = (uint8*)&gen_resp;
	sock_data.len = gen_resp.hdr.len;
	/* Send the data */
	if (afc_socket_send_data(childfd, &sock_data) <= 0) {
		AFC_ERROR("Failed to send response data on %d\n", childfd);
	}

	AFC_EXIT();
}

/* Process send Available Spectrum Inquiry Request message CLI command */
static void
afcd_process_send_req_cli_cmd(afcd_info_t *info, afc_cli_cmd_req_t *cmd_req, int childfd)
{
	int ret = AFCE_OK;
	afc_cli_cmd_general_resp_t gen_resp;
	afc_sock_data_t sock_data;
	AFC_ENTER();

	AFC_INFO("Send Available Spectrum Inquiry Request Message\n");

	ret = afc_read_available_spectrum_inquiry_request(&info->request_id,
			info->locpold_fd, &info->spec_inq_req_msg);
	AFC_INFO("Done. ret %d\n", ret);

	memset(&gen_resp, 0, sizeof(gen_resp));

	memcpy(&gen_resp.hdr, &cmd_req->hdr, sizeof(gen_resp.hdr));
	gen_resp.resp = ret;
	snprintf(gen_resp.resp_desc, sizeof(gen_resp.resp_desc), "%s", afcerrorstr(ret));
	gen_resp.hdr.len = sizeof(gen_resp);

	sock_data.data = (uint8*)&gen_resp;
	sock_data.len = gen_resp.hdr.len;

	/* Send the data */
	if (afc_socket_send_data(childfd, &sock_data) <= 0) {
		AFC_ERROR("Failed to send response data on %d\n", childfd);
	}

	AFC_EXIT();
}

/* Process Get Stored Available Spectrum Inquiry Response CLI command */
static void
afcd_process_get_stored_res_cli_cmd(afcd_info_t *info, afc_cli_cmd_stored_res_t *cmd_req,
	int childfd)
{
	int ret = AFCE_OK;
	afc_cli_cmd_general_resp_t gen_resp;
	afc_sock_data_t sock_data;
	AFC_ENTER();

	AFC_INFO("Get Stored Available Spectrum Inquiry Response\n");

	if (info->spec_inq_resp_msg.spec_inq_resp.count == 0) {
		ret = AFCE_NO_STORED_RES;
	}

	memset(&gen_resp, 0, sizeof(gen_resp));

	memcpy(&gen_resp.hdr, &cmd_req->hdr, sizeof(gen_resp.hdr));
	gen_resp.resp = ret;
	snprintf(gen_resp.resp_desc, sizeof(gen_resp.resp_desc), "%s", afcerrorstr(ret));
	gen_resp.hdr.len = sizeof(gen_resp);

	sock_data.data = (uint8*)&gen_resp;
	sock_data.len = gen_resp.hdr.len;

	/* Send the data */
	if (afc_socket_send_data(childfd, &sock_data) <= 0) {
		AFC_ERROR("Failed to send response data on %d\n", childfd);
	}

	AFC_EXIT();
}

/* Send the Available Spectrum Inquiry Response to WBD slave CLI */
static int
afcd_send_available_spectrum_inquiry_resp_to_wbd(afc_curl_output_t *curl_output, uint8 *al_mac)
{
	int ret = AFCE_OK;
	char *wbd_jason_data = NULL;
	afc_sock_data_t sock_data;
	AFC_ENTER();

	AFC_INFO("Send the Available Spectrum Inquiry Reesponse to WBD\n");
	memset(&sock_data, 0, sizeof(sock_data));

	wbd_jason_data = afc_json_wbd_data_from_response(curl_output->data, al_mac);
	if (!wbd_jason_data) {
		goto end;
	}

	sock_data.len = strlen(wbd_jason_data);
	sock_data.data = (uint8*)afc_malloc((sock_data.len + 1), &ret);
	if (!sock_data.data) {
		AFC_ERROR("Failed to allocate memory\n");
		goto end;
	}

	memcpy(sock_data.data, wbd_jason_data, sock_data.len);
	/* Include NULL as the WBD CLI expects NULL character in the end becuase it is a
	 * JSON string
	 */
	sock_data.len++;
	AFC_DEBUG("JSON Input to WBD System: Len %u \n%s\n", sock_data.len, sock_data.data);
	ret = afc_to_wbd_send(&sock_data);

end:
	/* Free the json data created from request */
	if (wbd_jason_data) {
		free(wbd_jason_data);
	}
	afc_free_sock_data(&sock_data);
	AFC_EXIT();
	return ret;
}

/* Check whether the cahced data is valid or not
 * TODO: Implementation pending
 */
static int
afcd_is_cache_valid(afc_cli_cmd_pass_req_t *pass_req, char **afc_resp)
{
	int ret = AFCE_OK;
	size_t afc_resp_sz = 0;
	afcd_info_t *info = afcd_get_ginfo();
	AFC_ENTER();

	/* Check for expiry. Calculate the expirty timeout from the response, If the timeout is 0
	 * means its already expired
	 */
	if (afc_get_available_spectrum_inquiry_req_timeout(&info->spec_inq_resp_msg) == 0) {
		AFC_INFO("Cached Spectrum Availability Response has expired\n");
		ret = AFCE_NO_STORED_RES;
		goto end;
	}

	/* If the AFC response is available locally in a file, read it and send it to repeater */
	AFC_INFO("Read Available Spectrum Inquiry Response from file(%s) if present\n",
		RESPONSE_JSON_FILENAME);

	if (afc_read_file(RESPONSE_JSON_FILENAME, afc_resp, &afc_resp_sz) <= 0) {
		ret = AFCE_NO_STORED_RES;
		goto end;
	}

	AFC_DEBUG("%zu bytes retrieved from file %s\n", afc_resp_sz, RESPONSE_JSON_FILENAME);
	AFC_DEBUG("file output : \n%s\n", *afc_resp);

	AFC_INFO("Cached Spectrum Availability Response is valid\n");

end:
	AFC_EXIT();
	return ret;
}

/* Send the cached Available Spectrum Inquiry Response if available to the repeater */
static int
afcd_send_back_cached_response(afc_cli_cmd_pass_req_t *pass_req)
{
	int ret = AFCE_OK;
	afc_curl_output_t curl_output;
	char request_id[AFC_MAX_STR_REQ_ID] = {0};
	char *afc_resp = NULL;
	AFC_ENTER();

	memset(&curl_output, 0, sizeof(curl_output));

	/* Check whether the cahced data is valid or not */
	if (afcd_is_cache_valid(pass_req, &afc_resp) != AFCE_OK) {
		/* For now, just don't request the server for fresh data, let the repeater request
		 * again as another thread in AFCD will already be requesting the AFC server for
		 * fresh data
		 */
		ret = AFCE_OK;
		goto end;
	}

	/* We need to send the response with the same request ID which is there in the request.
	 * So, get the request ID from the request and replace it in the response
	 */
	ret = afc_json_get_request_id_from_request(pass_req->req, request_id, sizeof(request_id));
	AFC_ASSERT();

	curl_output.data = afc_json_update_request_id_in_response(request_id, afc_resp);
	if (!curl_output.data) {
		goto end;
	}
	curl_output.size = strlen(curl_output.data);

	/* Send the response to WBD */
	afcd_send_available_spectrum_inquiry_resp_to_wbd(&curl_output, pass_req->al_mac);

end:
	/* Free the JSON data got after updating request ID */
	if (curl_output.data) {
		free(curl_output.data);
	}
	/* Free read file data */
	if (afc_resp) {
		free(afc_resp);
	}

	AFC_EXIT();
	return ret;
}

/* Callback function to send Available Spectrum Inquiry Request from WBD to AFC server */
static void
afcd_pass_req_from_wbd_timer_cb(bcm_usched_handle *hdl, void *arg)
{
	int ret = AFCE_OK;
	afc_cli_cmd_pass_req_t *pass_req = (afc_cli_cmd_pass_req_t*)arg;
	afc_curl_output_t curl_output;
	AFC_ENTER();

	memset(&curl_output, 0, sizeof(curl_output));
	if (!pass_req || !pass_req->req) {
		AFC_WARNING("Available Spectrum Inquiry Request Data is NULL\n");
		goto end;
	}

	AFC_DEBUG("JSON Input to AFC System from repeater Len[%zu]: \n%s\n", strlen(pass_req->req),
		pass_req->req);

	/* Send the cached Available Spectrum Inquiry Response if available to the repeater */
	if (afcd_send_back_cached_response(pass_req) == AFCE_OK) {
		goto end;
	}

	AFC_INFO("Pass the Available Spectrum Inquiry Request from WBD to AFC server\n");

	/* An Available Spectrum Inquiry Request message is sent by an AFC Device to an AFC System
	 * or retrieval of Available Spectrum information, and an Available Spectrum Inquiry
	 * Response message is sent by an AFC System responding to the Available Spectrum Inquiry
	 * Request message sent by the AFC Device
	 */
	ret = afc_curl_send_request(&g_afcdinfo->spec_inq_req_msg, pass_req->req,
		AFC_METHOD_AVAILABLE_SPECTRUM_INQUIRY, &curl_output);
	if (ret == 0) {
		AFC_DEBUG("%zu bytes retrieved from AFC System\n", curl_output.size);
		AFC_DEBUG("JSON output from AFC System : \n%s\n", curl_output.data);
		afcd_send_available_spectrum_inquiry_resp_to_wbd(&curl_output, pass_req->al_mac);
	}

end:
	/* Free the JSON data received from server */
	if (curl_output.data) {
		free(curl_output.data);
	}
	if (pass_req) {
		if (pass_req->req) {
			free(pass_req->req);
		}
		free(pass_req);
	}

	AFC_EXIT();
}

/* Pass the Available Spectrum Inquiry Request from WBD to AFC server CLI command
 * Format of CLI : HDR + 6 bytes of AL_MAC + AFC Request string in JSON format
 */
static void
afcd_process_pass_req_from_wbd_cli_cmd(afcd_info_t *info, afc_sock_data_t *sock_data, int childfd)
{
	int ret = AFCE_OK;
	uint32 len = 0;
	uint8 *data;
	afc_cli_cmd_hdr_t *hdr;
	afc_cli_cmd_pass_req_t *pass_req = NULL;
	afc_cli_cmd_general_resp_t gen_resp;
	afc_sock_data_t resp_sock_data;
	AFC_ENTER();

	hdr = (afc_cli_cmd_hdr_t*)sock_data->data;

	AFC_INFO("Pass the Available Spectrum Inquiry Request from WBD to AFC server CLI "
		"Command\n");
	/* Do not accept this command if the AFCD is running in proxy mode */
	if (info->mode == AFCD_MODE_PROXY) {
		ret = AFCE_INV_CLI_PASS_REQ;
	}
	memset(&gen_resp, 0, sizeof(gen_resp));

	memcpy(&gen_resp.hdr, hdr, sizeof(gen_resp.hdr));
	gen_resp.resp = ret;
	snprintf(gen_resp.resp_desc, sizeof(gen_resp.resp_desc), "%s", afcerrorstr(ret));
	gen_resp.hdr.len = sizeof(gen_resp);

	resp_sock_data.data = (uint8*)&gen_resp;
	resp_sock_data.len = gen_resp.hdr.len;

	/* Send the response back to WBD */
	if (afc_socket_send_data(childfd, &resp_sock_data) <= 0) {
		AFC_ERROR("Failed to send response data on %d\n", childfd);
	}

	if (info->mode == AFCD_MODE_PROXY) {
		AFC_INFO("Invalid CLI command in Proxy mode. Proxy mode will not contact AFC "
			"server directly to send the Available Spectrum Inquiry Request\n");
		goto end;
	}

	/* Create a 0 seconds timer to handle the request. This is just not to block the WBD agent
	 * as the AFC server contacting might take some time
	 */
	pass_req = (afc_cli_cmd_pass_req_t*)afc_malloc(sizeof(*pass_req), &ret);
	if (pass_req == NULL) {
		AFC_ERROR("Failed to allocated memory\n");
		goto end;
	}

	memcpy(&pass_req->hdr, hdr, sizeof(pass_req->hdr));
	data = sock_data->data;
	len = sock_data->len;
	data += sizeof(afc_cli_cmd_hdr_t);
	len -= sizeof(afc_cli_cmd_hdr_t);
	memcpy(pass_req->al_mac, data, sizeof(pass_req->al_mac));
	data += sizeof(pass_req->al_mac);
	len -= sizeof(pass_req->al_mac);
	if (len == 0) {
		ret = AFCE_INV_ARG;
		AFC_ERROR("Request length is 0\n");
		goto end;
	}
	pass_req->req = (char*)afc_malloc((len + 1), &ret);
	if (pass_req->req == NULL) {
		AFC_ERROR("Failed to allocate memory for AFC request\n");
		goto end;
	}
	memcpy(pass_req->req, data, len);

	ret = afcd_add_timers(info->usched_hdl, pass_req, AFCD_SEC_MICROSEC(0),
		afcd_pass_req_from_wbd_timer_cb, 0);

end:
	if ((ret != AFCE_OK) && pass_req) {
		if (pass_req->req) {
			free(pass_req->req);
		}
		free(pass_req);
	}
	AFC_EXIT();
}

/* Process the Received Spectrum Inquiry Response from WBD
 * Format of CLI : HDR + 6 bytes of AL_MAC + AFC Request string in JSON format
 */
static void
afcd_process_pass_resp_from_wbd_cli_cmd(afcd_info_t *info, afc_sock_data_t *sock_data, int childfd)
{
	int ret = AFCE_OK;
	uint32 len = 0;
	uint8 *data;
	afc_cli_cmd_hdr_t *hdr;
	afc_cli_cmd_general_resp_t gen_resp;
	afc_sock_data_t resp_sock_data;
	AFC_ENTER();

	hdr = (afc_cli_cmd_hdr_t*)sock_data->data;

	AFC_INFO("Process the Received Spectrum Inquiry Response from WBD\n");
	/* Accept this command if the AFCD is running in proxy mode only */
	if (info->mode != AFCD_MODE_PROXY) {
		ret = AFCE_INV_CLI_PASS_RESP;
	}
	memset(&gen_resp, 0, sizeof(gen_resp));

	memcpy(&gen_resp.hdr, hdr, sizeof(gen_resp.hdr));
	gen_resp.resp = ret;
	snprintf(gen_resp.resp_desc, sizeof(gen_resp.resp_desc), "%s", afcerrorstr(ret));
	gen_resp.hdr.len = sizeof(gen_resp);

	memset(&resp_sock_data, 0, sizeof(resp_sock_data));

	resp_sock_data.data = (uint8*)&gen_resp;
	resp_sock_data.len = gen_resp.hdr.len;

	/* Send the response back to WBD */
	if (afc_socket_send_data(childfd, &resp_sock_data) <= 0) {
		AFC_ERROR("Failed to send response data on %d\n", childfd);
	}

	if (info->mode != AFCD_MODE_PROXY) {
		AFC_INFO("Invalid CLI command in Non Proxy mode. Only Proxy mode will act on AFC "
			"Spectrum Inquiry Resiponse received from WBD\n");
		return;
	}

	data = sock_data->data;
	len = sock_data->len;
	data += sizeof(afc_cli_cmd_hdr_t);
	len -= sizeof(afc_cli_cmd_hdr_t);
	if (len == 0) {
		AFC_ERROR("Request length is 0\n");
		return;
	}
	AFC_DEBUG("%u bytes retrieved from AFC System\n", len);
	AFC_DEBUG("JSON output from AFC System : \n%s\n", data);

	/* Process the JSON response and store it in structure */
	ret = afc_json_parse_response_data((char *)data, len, &info->spec_inq_resp_msg);
	if (ret == AFCE_OK) {
		afc_write_to_file(RESPONSE_JSON_FILENAME, (char *)data, len);
		ret = afc_consume_available_spectrum_inquiry_response(&info->spec_inq_resp_msg);
	}

	/* Create the next timer again */
	afcd_create_inquiry_request_timer(info, (ret == AFCE_OK));

	AFC_EXIT();
}

/* Process CLI commands */
static int
afcd_process_cli_cmds(afcd_info_t *info, int childfd, afc_sock_data_t *sock_data)
{
	afc_cli_cmd_hdr_t *hdr;
	AFC_ENTER();

	hdr = (afc_cli_cmd_hdr_t*)sock_data->data;

	switch (hdr->cmd) {
		case AFC_CMD_CLI_MSGLEVEL:
		{
			afcd_process_msglevel_cli_cmd((afc_cli_cmd_msglevel_t*)sock_data->data,
				childfd);
		}
		break;
		case AFC_CMD_CLI_SEND_REQ:
		{
			afcd_process_send_req_cli_cmd(info, (afc_cli_cmd_req_t*)sock_data->data,
				childfd);
		}
		break;
		case AFC_CMD_CLI_STORED_RES:
		{
			afcd_process_get_stored_res_cli_cmd(info,
				(afc_cli_cmd_stored_res_t*)sock_data->data, childfd);
		}
		break;
		case AFC_CMD_CLI_PASS_REQ:
		{
			afcd_process_pass_req_from_wbd_cli_cmd(info, sock_data, childfd);
		}
		break;
		case AFC_CMD_CLI_PASS_RESP:
		{
			afcd_process_pass_resp_from_wbd_cli_cmd(info, sock_data, childfd);
		}
		break;
		default:
			AFC_ERROR("Unknown command %d\n", hdr->cmd);
	}

	AFC_EXIT();
	return AFCE_OK;
}

/* Callback function called from scheduler library to process CLI data */
static void
afcd_process_cli_fd_cb(bcm_usched_handle *handle, void *arg, bcm_usched_fds_entry_t *entry)
{
	int ret = AFCE_SOCKET, rcv_ret;
	afcd_info_t *info = (afcd_info_t*)arg;
	afc_sock_data_t sock_data;
	int childfd = AFC_INVALID_SOCKET;
	AFC_ENTER();

	memset(&sock_data, 0, sizeof(sock_data));

	/* Accept the connection */
	if ((childfd = afc_accept_connection(entry->fd)) == AFC_INVALID_SOCKET) {
		AFC_WARNING("Failed to accept client connection on sockfd[%d], %s\n",
			entry->fd, afcerrorstr(AFCE_SOCKET));
		goto end;
	}

	/* Get the data from client */
	rcv_ret = afc_socket_recv_data(childfd, &sock_data);
	if ((rcv_ret <= 0)) {
		AFC_WARNING("Failed to recieve data on child socket %d of main socket %d. "
			"Error code : %d\n", childfd, entry->fd, rcv_ret);
		goto end;
	}

	ret = afcd_process_cli_cmds(info, childfd, &sock_data);

end:
	afc_free_sock_data(&sock_data);
	afc_close_socket(&childfd);
	AFC_DEBUG("Process CLI command ret %d\n", ret);
	AFC_EXIT();

	return;
}

/* Return FALSE when both location and location_successive used at least once for evaluating
 * afc response and sp gain otherwise TRUE.
 */
static bool
afcd_is_any_location_evaluation_pending(avl_spec_inq_req_msg_t *spec_inq_req_msg)
{
	avl_spec_inq_req_t *spec_inq_req = NULL;
	dll_t *spec_inq_req_item_p;
	bool ret = FALSE;

	AFC_ENTER();

	if (spec_inq_req_msg->spec_inq_req.count <= 0) {
		goto end;
	}

	foreach_glist_item(spec_inq_req_item_p, spec_inq_req_msg->spec_inq_req) {
		spec_inq_req = (avl_spec_inq_req_t*)spec_inq_req_item_p;
		break;
	}

	ret = ((spec_inq_req->location.flags & AFC_LOCATION_FLAG_VALID) &&
		!(spec_inq_req->location.flags & AFC_LOCATION_FLAG_USED)) ||
		((spec_inq_req->location_successive.flags & AFC_LOCATION_FLAG_VALID) &&
		!(spec_inq_req->location_successive.flags & AFC_LOCATION_FLAG_USED));
end:
	AFC_EXIT();

	return ret;
}

/* Copies the location from locpold response msg to local afc structure */
static void
afcd_store_location(afc_location_t *location, ipc_resp_t *resp)
{
	AFC_ENTER();

	location->ellipse.center.latitude = resp->resp.location.loc.loc.ellipse.latitude;
	location->ellipse.center.longitude = resp->resp.location.loc.loc.ellipse.longitude;
	location->ellipse.major_axis = (int32)ceil(resp->resp.location.loc.loc.ellipse.major_axis);
	location->ellipse.minor_axis = (int32)ceil(resp->resp.location.loc.loc.ellipse.minor_axis);
	location->ellipse.orientation =
		(int32)ceil(resp->resp.location.loc.loc.ellipse.orientation);
	location->elevation.height = (int32)ceil(resp->resp.location.loc.loc.ellipse.altitude);
	snprintf(location->elevation.height_type, sizeof(location->elevation.height_type), "%s",
		(resp->resp.location.loc.loc.ellipse.altitude_type == 0 ? "AGL" : "AMSL"));
	location->elevation.vertical_uncertainty =
		(int32)ceil(resp->resp.location.loc.loc.ellipse.altitude_uncertainty);
	location->flags |= AFC_LOCATION_FLAG_VALID;

	AFC_EXIT();
}

/* Process the location response received from locpold */
static void
afc_process_locpold_resp(void *arg, ipc_resp_t *resp)
{
	afcd_info_t *info = (afcd_info_t *)arg;
	avl_spec_inq_req_t *spec_inq_req = NULL;
	avl_spec_inq_req_msg_t *spec_inq_req_msg;
	dll_t *spec_inq_req_item_p;
	uint32 seq_no_diff = 0;

	AFC_ENTER();

	AFC_INFO("header info: type=0x%x, len=%u, status=%d timestamp=%lld, seq=%u\n",
			resp->hdr.msg_type, resp->hdr.len, resp->hdr.status,
			(long long)resp->hdr.timestamp, resp->hdr.seq_no);

	spec_inq_req_msg = &info->spec_inq_req_msg;
	if (spec_inq_req_msg->spec_inq_req.count <= 0) {
		AFC_INFO("Available Spectrum Inquiry Request entries not present\n");
		goto end;
	}

	foreach_glist_item(spec_inq_req_item_p, spec_inq_req_msg->spec_inq_req) {
		spec_inq_req = (avl_spec_inq_req_t*)spec_inq_req_item_p;
		break;
	}

	/* validate response header */
	if ((resp->hdr.msg_type != RESP_LD_AD_LOC_REQ && resp->hdr.msg_type != NOTIF_LD_AD_LOC) ||
			resp->hdr.status != LOCPOL_SUCCESS ||
			resp->hdr.len < sizeof(resp->resp.location)) {
		AFC_INFO("Locpold msg_type/expected:[0x%04x]/[0x%4x or 0x%4x], "
				"status/expected:[%d]/[%d], len/expected:[%u]/[%zu]\n",
				resp->hdr.msg_type, RESP_LD_AD_LOC_REQ, NOTIF_LD_AD_LOC,
				resp->hdr.status, LOCPOL_SUCCESS,
				resp->hdr.len, sizeof(resp->resp.location));
		goto end;
	}

	/* validate response seq_no is within range. */
	seq_no_diff = (resp->hdr.seq_no > spec_inq_req->seq_no) ?
		(resp->hdr.seq_no - spec_inq_req->seq_no) :
		(spec_inq_req->seq_no - resp->hdr.seq_no);
	if (seq_no_diff > AFC_LOCPOLD_MAX_SEQ_OFF) {
		AFC_INFO("Locpold resp seq_no:%u, req seq_no:%u (expected within %d offset)\n",
				resp->hdr.seq_no, spec_inq_req->seq_no, AFC_LOCPOLD_MAX_SEQ_OFF);
		goto end;
	}

	if (resp->resp.location.loc.loc.ellipse.longitude == AFC_DEF_LONGITUDE &&
			resp->resp.location.loc.loc.ellipse.latitude == AFC_DEF_LATITUDE) {
		AFC_INFO("GeoLoc Ellipse center is missing : Longitude [%.17g], Latitude[%.17g]\n",
				resp->resp.location.loc.loc.ellipse.longitude,
				resp->resp.location.loc.loc.ellipse.longitude);
		goto end;
	}

	AFC_INFO("location data: lat=%f, lon=%f, major_axis:%f, minor_axis:%f, "
			"orientation:%f, height:%f, height_type:%u, "
			"vertical_uncertainty=%f\n",
			resp->resp.location.loc.loc.ellipse.latitude,
			resp->resp.location.loc.loc.ellipse.longitude,
			resp->resp.location.loc.loc.ellipse.major_axis,
			resp->resp.location.loc.loc.ellipse.minor_axis,
			resp->resp.location.loc.loc.ellipse.orientation,
			resp->resp.location.loc.loc.ellipse.altitude,
			resp->resp.location.loc.loc.ellipse.altitude_type,
			resp->resp.location.loc.loc.ellipse.altitude_uncertainty);

	if (info->state == AFCD_SATIATED) {
		AFC_INFO("Skip processing the location notification as afcd has multiple full-bw "
				"chanspec with satisfactory sp gain(satiated state)\n");
		goto end;
	}

	/* convert/copy to afcd location structure intial response will be stored in location
	 * variable however successive fixes will be stored in location_successive variable.
	 */
	 if (!(spec_inq_req->location.flags & AFC_LOCATION_FLAG_VALID)) {
		afcd_store_location(&spec_inq_req->location, resp);
	} else {
		afcd_store_location(&spec_inq_req->location_successive, resp);
	}

	AFC_INFO("Curl Tiemout[%d] URL[%s] Version[%s] Request ID[%s] "
			"TLS cacert[%s] mTLS cert[%s]\n",
			spec_inq_req_msg->curl_wait_timeout, spec_inq_req_msg->base_url,
			spec_inq_req_msg->req_version, spec_inq_req->request_id,
			(spec_inq_req_msg->tls_cacert ? spec_inq_req_msg->tls_cacert : ""),
			(spec_inq_req_msg->mtls_cert ? spec_inq_req_msg->mtls_cert : ""));

	if (!AFC_REQ_IS_LOCATION_USE_IN_PROGRESS(spec_inq_req_msg->flags)) {
		spec_inq_req_msg->flags |= AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS;
		if (afcd_process_spec_inq_req(spec_inq_req) != AFCE_OK) {
			spec_inq_req_msg->flags &= ~AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS;
		}
	}

end:
	AFC_EXIT();
}

/* Callback function called from scheduler library to process CLI data */
static void
afcd_process_locpold_fd_cb(bcm_usched_handle *handle, void *arg, bcm_usched_fds_entry_t *entry)
{
	int ret;
	ipc_resp_t resp;
	afcd_info_t *info = (afcd_info_t *)arg;

	AFC_ENTER();

	memset(&resp, 0, sizeof(resp));

	ret = read(entry->fd, &resp, sizeof(resp));
	if (ret == 0) {
		AFC_INFO("Closing locpol socket %d\n", entry->fd);
		if (afcd_remove_fd(info->usched_hdl, info->locpold_fd) != AFCE_OK) {
			AFC_ERROR("Failed to remove locpold fd from scheduler\n");
			goto end;
		}
		afc_close_socket(&info->locpold_fd);
		goto end;
	}
	if (ret < 0) {
		AFC_ERROR("Failed to recieve data on locpol socket %d ret %d\n",
			entry->fd, ret);
		goto end;
	}

	afc_process_locpold_resp(arg, &resp);
end:
	AFC_EXIT();
}

/* Add FD to micro scheduler */
int
afcd_add_fd_to_schedule(bcm_usched_handle *hdl, int fd, void *arg, bcm_usched_fdscbfn *cbfn)
{
	int ret = AFCE_OK;
	int fdbits = 0;
	BCM_USCHED_STATUS status = 0;
	AFC_ENTER();

	if (fd != AFC_INVALID_SOCKET) {
		BCM_USCHED_SETFDMASK(fdbits, BCM_USCHED_MASK_READFD);
		status = bcm_usched_add_fd_schedule(hdl, fd, fdbits, cbfn, arg);
		if (status != BCM_USCHEDE_OK) {
			AFC_WARNING("Failed to add FD[%d]. Error : %s\n", fd,
				bcm_usched_strerror(status));
			ret = AFCE_USCHED_ERROR;
			goto end;
		}
	}

end:
	AFC_EXIT();
	return ret;
}

/* Remove a file descriptor form the micro scheduler. */
static int
afcd_remove_fd(bcm_usched_handle *hdl, int fd)
{
	int ret = AFCE_OK;
	BCM_USCHED_STATUS status = 0;
	AFC_ENTER();

	if (fd != AFC_INVALID_SOCKET) {
		status = bcm_usched_remove_fd_schedule(hdl, fd);
		if (status != BCM_USCHEDE_OK) {
			AFC_WARNING("Failed to remove FD[%d]. Error : %s\n", fd,
				bcm_usched_strerror(status));
			ret = AFCE_USCHED_ERROR;
			goto end;
		}
	}

end:
	AFC_EXIT();
	return ret;
}

/*
 * Tries to open socket with locpold and add it to the usched lib.
 * On success returns the locpold socket fd otherwise -1.
 */
static int
afcd_open_and_add_locpold_sock_to_schedule()
{
	assert(g_afcdinfo);
	assert(g_afcdinfo->usched_hdl);

	if (g_afcdinfo->locpold_fd != AFC_INVALID_SOCKET) {
		return g_afcdinfo->locpold_fd;
	}

	g_afcdinfo->locpold_fd = afc_try_to_get_locpold_fd();
	if (g_afcdinfo->locpold_fd == AFC_INVALID_SOCKET) {
		AFC_ERROR("Failed to get locpold fd \n");
		return AFC_INVALID_SOCKET;
	}

	if (afcd_add_fd_to_schedule(g_afcdinfo->usched_hdl, g_afcdinfo->locpold_fd,
			g_afcdinfo, afcd_process_locpold_fd_cb) != AFCE_OK) {
		AFC_ERROR("Failed to add locpold fd to schedule\n");
		afc_close_socket(&g_afcdinfo->locpold_fd);
		return AFC_INVALID_SOCKET;
	}

	AFC_INFO("Successfully added locpold fd(%d) to scheduler\n", g_afcdinfo->locpold_fd);
	return g_afcdinfo->locpold_fd;
}

/* Process the spectrum inquiry request having the updated location data */
static int
afcd_process_spec_inq_req(avl_spec_inq_req_t *spec_inq_req)
{
	int ret = AFCE_OK;

	assert(g_afcdinfo);
	assert(spec_inq_req);

	afc_read_frequency_range(spec_inq_req);
	afc_read_inquired_channels(spec_inq_req);
	spec_inq_req->min_desired_pwr = AFC_DEFAULT_MIN_DESIRED_EIRP;
	ret = afcd_perform_available_spectrum_inquiry_req(g_afcdinfo);

	return ret;
}

/* Allocate & Initialize the info structure */
static afcd_info_t*
afcd_info_init(int *error, int mode)
{
	int ret = AFCE_OK, tmpret, num_if_6g = 0;
	afcd_info_t *info = NULL;
	char *val, if_6g[IFNAMSIZ * AFCD_MAX_IFACE], ifname[IFNAMSIZ] = {0}, *next_ifname;

	AFC_ENTER();

	/* Allocate the info structure */
	info = (afcd_info_t*)afc_malloc(sizeof(*info), &ret);
	AFC_ASSERT_MSG("AFC Info alloc failed... Aborting...\n");

	info->mode = (uint8)mode;
	info->request_id = (int32) (((unsigned long)(time(NULL))) & INT_MAX); /* unique first id */
	info->state = AFCD_BOOTUP;

	num_if_6g = wl_wlif_get_wlan_ifnames(if_6g, sizeof(if_6g), WLC_BAND_6G);
	AFC_INFO("Total WLAN %d. Num 6GHz radios: %d (%s)\n",
			wl_wlif_get_wlan_ifnames(NULL, 0, WLC_BAND_ALL),
			num_if_6g, if_6g);
	foreach(ifname, if_6g, next_ifname) {
		AFCSTRNCPY(g_afc_ifnames[g_afc_num_ifnames], ifname, IFNAMSIZ);
		AFC_PRINT("Info: ", "AFCD 6GHz AFC interface[%d]='%s'\n",
				g_afc_num_ifnames, g_afc_ifnames[g_afc_num_ifnames]);
		afc_init_swap(ifname);
		g_afc_num_ifnames++;
		if (g_afc_num_ifnames >= AFCD_MAX_IFACE) {
			AFC_INFO("Already included %d (max) interfaces\n", AFCD_MAX_IFACE);
			break;
		}
	}

	if (g_afc_num_ifnames == 0) {
		AFC_ERROR("Exiting AFCD. No 6GHz AFC interfaces found yet!!!\n");
		ret = AFCE_INV_ARG;
		goto end;
	}
	AFC_PRINT("Info: ", "AFCD %d 6GHz AFC interface(s) found\n", g_afc_num_ifnames);

	/* Get the IEEE1905 agent AL MAC address only if the AFCD running in proxy mode */
	if (info->mode == AFCD_MODE_PROXY) {
		val = afc_nvram_safe_get(AFC_NVRAM_1905_AL_MAC);
		if (strlen(val) > 0) {
			ether_atoe(val, info->spec_inq_req_msg.al_mac.octet);
		}
	}

	info->web_req_gap = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_MIN_REQ_GAP,
		AFC_DEF_MIN_REQ_GAP);

	info->usched_hdl = bcm_usched_init();
	if (info->usched_hdl == NULL) {
		AFC_ERROR("Failed to create usched handle\n");
		ret = AFCE_USCHED_ERROR;
		goto end;
	}

	info->cli_server_fd = AFC_INVALID_SOCKET;

	/* Try to open the server FD for CLI */
	info->cli_server_fd = afc_try_open_server_fd(EAPD_WKSP_AFC_TCP_CLI_PORT, &ret);
	AFC_ASSERT_MSG("Failed to create CLI socket\n");

	ret = afcd_add_fd_to_schedule(info->usched_hdl, info->cli_server_fd,
		info, afcd_process_cli_fd_cb);
	AFC_ASSERT();

	/* Read Available Spectrum Inquiry Response from file and store it in a structure */
	tmpret = afc_read_available_spectrum_inquiry_response_from_file(&info->spec_inq_resp_msg);
	if (tmpret != AFCE_OK) {
		info->spec_inq_resp_msg.flags |= AFC_RESP_FLAGS_RESP_EXPIRED;
		AFC_INFO("Failed to Read Available Spectrum Inquiry Response from file. "
			"Error[%s]\n", afcerrorstr(tmpret));
	} else {
		AFC_INFO("Successfully Read Available Spectrum Inquiry Response from file\n");
		info->state = AFCD_KNOWN_LOCATION_UNKNOWN_SP_GAIN;
		afcd_create_sp_gain_check_timer(info);
	}

	afcd_next_action_on_state_change(info);
	info->locpold_fd = AFC_INVALID_SOCKET;
	info->spec_inq_req_msg.afc_get_lockpold_sock = afcd_open_and_add_locpold_sock_to_schedule;
	info->spec_inq_req_msg.afc_process_spec_inq_req_item = afcd_process_spec_inq_req;

	AFC_INFO("Info init done\n");

end:
	if (error) {
		*error = ret;
	}
	AFC_EXIT();
	return info;
}

/* Exit the AFC module */
static void
afcd_exit(afcd_info_t *info)
{
	AFC_ENTER();

	if (!info) {
		return;
	}

	afc_cleanup_available_spectrum_inquiry_request_list(&info->spec_inq_req_msg);

	afc_cleanup_available_spectrum_inquiry_response_list(&info->spec_inq_resp_msg);

	afc_close_socket(&info->cli_server_fd);
	afc_close_socket(&info->locpold_fd);

	/* Stop the scheduler and deinit */
	if (info->usched_hdl) {
		bcm_usched_stop(info->usched_hdl);
		bcm_usched_deinit(info->usched_hdl);
	}

	free(info);

	AFC_INFO("Info Cleanup Done\n");

	g_afcdinfo = NULL;

	AFC_EXIT();
}

void afcd_toggle_syslog(afcd_info_t *info)
{
	AFC_ENTER();

	if (!info) {
		return;
	}

	if (!info->std_out_err.out && !info->std_out_err.err) {
		openlog("afcd", LOG_ODELAY, LOG_USER);
		redirect_std_out_err_to_syslog(&info->std_out_err);
	} else {
		restore_std_out_err(&info->std_out_err);
		closelog();
	}

	AFC_EXIT();
}

/* Signal handler */
void
afcd_signal_hdlr(int sig)
{
	AFC_ENTER();

	switch (sig) {
		case SIGUSR2:
			AFC_ERROR("Signal : %d toggling syslog\n", sig);
			afcd_toggle_syslog(afcd_get_ginfo());
			break;
		default:
			AFC_ERROR("Signal : %d unhandled\n", sig);
			break;
	}
	AFC_EXIT();
}

/* Common cli usage printing fn for master and slave apps */
static void
afcd_print_cli_usage(int argc, char **argv)
{
	printf("\n %s command line options:\n", ((argc > 1) ? argv[0] : ""));
	printf("-f Foreground\n"
		"-r Test the JSON Request Creation\n"
		"-p Test the JSON Parse from the data stroed in file %s\n"
		"-o Perform full operation of create send and parse\n"
		"-h Show help\n", RESPONSE_JSON_FILENAME);
}

/* Parse common cli arguments for master and slave apps */
uint16
afcd_parse_cli_args(int argc, char *argv[])
{
	int c;
	uint16 cmd = 0;
	AFC_ENTER();

	while ((c = getopt(argc, argv, "hHfFrRpPoO")) != -1) {
		switch (c) {
			case 'f':
			case 'F':
				cmd |= AFCD_CMD_FLAG_FOREGROUND;
				AFC_DEBUG("Foreground\n");
				break;
			case 'r':
			case 'R':
				cmd |= AFCD_CMD_FLAG_TEST_REQ;
				AFC_DEBUG("Test JSON Request Creation\n");
				break;
			case 'p':
			case 'P':
				cmd |= AFCD_CMD_FLAG_TEST_RESP;
				AFC_DEBUG("Test Parse JSON Response From File\n");
				break;
			case 'o':
			case 'O':
				cmd |= AFCD_CMD_FLAG_FULL_OP;
				AFC_DEBUG("Test Full Operation\n");
				break;
			case 'h':
			case 'H':
				afcd_print_cli_usage(argc, argv);
				AFC_DEBUG("Help\n");
				exit(0);
				break;
			default:
				AFC_WARNING("%s invalid option %c %x\n", argv[0], optopt, c);
				afcd_print_cli_usage(argc, argv);
				exit(0);
		}
	}

	if (cmd <= 0) {
		if (daemon(1, 1) == -1) {
			perror("daemon");
			exit(errno);
		}
	}

	AFC_EXIT();
	return cmd;
}

/* Test the JSON Request Creation. Creates JSON data from strcuture and prints the JSON string */
void
afcd_test_json_req_creation(avl_spec_inq_req_msg_t *spec_inq_req_msg)
{
	char *json_data = NULL;
	AFC_ENTER();

	AFC_INFO("Test JSON Data Creation\n");

	json_data = (char*)afc_json_data_from_request(spec_inq_req_msg);
	if (!json_data) {
		goto end;
	}
	AFC_DEBUG("Input: \n%s\n", json_data);

end:
	if (json_data) {
		free(json_data);
	}
	AFC_EXIT();
}

/* Test the JSON Parse from the data stored in file RESPONSE_JSON_FILENAME */
static void
afcd_test_parse_json_response()
{
	afc_avl_spec_inq_resp_msg_t spec_inq_resp_msg;
	AFC_ENTER();

	AFC_INFO("Test JSON Data Parse\n");

	memset(&spec_inq_resp_msg, 0, sizeof(spec_inq_resp_msg));

	afc_read_available_spectrum_inquiry_response_from_file(&spec_inq_resp_msg);

	afc_cleanup_available_spectrum_inquiry_response_list(&spec_inq_resp_msg);

	AFC_EXIT();
}

/* Add timers to micro scheduler */
static int
afcd_add_timers(bcm_usched_handle *hdl, void *arg, unsigned long long timeout,
	bcm_usched_timerscbfn *cbfn, int repeat_flag)
{
	int ret = AFCE_OK;
	BCM_USCHED_STATUS status = 0;
	AFC_ENTER();

	AFC_DEBUG("Create timer of %llu usec. arg[%p] cbfn[%p]\n", timeout, arg, cbfn);

	status = bcm_usched_add_timer(hdl, timeout, repeat_flag, cbfn, arg);
	if (status != BCM_USCHEDE_OK) {
		AFC_WARNING("Timeout[%llu]usec arg[%p] cbfn[%p] Failed to add Timer. Error : %s\n",
			timeout, arg, cbfn, bcm_usched_strerror(status));
		if (status == BCM_USCHEDE_TIMER_EXISTS) {
			ret = AFCE_USCHED_TIMER_EXIST;
		} else {
			ret = AFCE_USCHED_ERROR;
		}
		goto end;
	}

end:
	AFC_EXIT();
	return ret;
}

/* Remove timers fm micro scheduler */
static int
afcd_remove_timers(bcm_usched_handle *hdl, bcm_usched_timerscbfn *cbfn, void *arg)
{
	int ret = AFCE_OK;
	BCM_USCHED_STATUS status = 0;
	AFC_ENTER();

	AFC_DEBUG("Remove Timer arg[%p] cbfn[%p]\n", arg, cbfn);

	status = bcm_usched_remove_timer(hdl, cbfn, arg);
	if (status != BCM_USCHEDE_OK) {
		AFC_WARNING("arg[%p] cbfn[%p] Failed to Remove Timer. Error : %s\n", arg, cbfn,
			bcm_usched_strerror(status));
		ret = AFCE_USCHED_ERROR;
		goto end;
	}

end:
	AFC_EXIT();
	return ret;
}

/* Callback function to perform Available Spectrum Inquiry Request */
static void
afcd_available_spectrum_inquiry_req_timer_cb(bcm_usched_handle *hdl, void *arg)
{
	int ret = AFCE_OK;
	afcd_info_t *info = (afcd_info_t*)arg;
	AFC_ENTER();

	AFC_INFO("Available Spectrum Inquiry Response is expired. Get fresh one\n");

	if (info->mode == AFCD_MODE_PROXY) {
		afcd_send_available_spectrum_inquiry_req_to_wbd(g_afcdinfo);
		goto end;
	}

	ret = afc_read_available_spectrum_inquiry_request(&info->request_id, info->locpold_fd,
			&info->spec_inq_req_msg);
	AFC_ASSERT();

end:
	/* Create the next timer again */
	afcd_create_inquiry_request_timer(info, (ret == AFCE_OK));

	AFC_EXIT();
}

/* Create timer to perform Available Spectrum Inquiry Request once expired */
static void
afcd_create_inquiry_request_timer(afcd_info_t *info, bool last_web_req_status)
{
	uint32 timeout;
	AFC_ENTER();

	afcd_update_web_req_gap(info, last_web_req_status);

	if (AFCD_IS_INQ_REQ_TIMER_EXISTS(info->flags)) {
		afcd_remove_timers(info->usched_hdl, afcd_available_spectrum_inquiry_req_timer_cb,
			info);
		info->flags &= ~AFCD_INFO_FLAGS_INQ_REQ_TIMER_EXISTS;
	}

	timeout = afc_get_available_spectrum_inquiry_req_timeout(&info->spec_inq_resp_msg);
	if (timeout > AFC_TIMEOUT_ADVANCE) {
		timeout -= AFC_TIMEOUT_ADVANCE;
	}

	if (timeout < info->web_req_gap) {
		timeout = info->web_req_gap;
	}

	AFC_INFO("Create timer to perform Available Spectrum Inquiry Request Message "
			"in %u seconds state %d request msg flags 0x%x response msg flags 0x%x\n",
			timeout, info->state, info->spec_inq_req_msg.flags,
			info->spec_inq_resp_msg.flags);

	if (afcd_add_timers(info->usched_hdl, info, AFCD_SEC_MICROSEC(timeout),
			afcd_available_spectrum_inquiry_req_timer_cb, 0) == AFCE_OK) {
		info->flags |= AFCD_INFO_FLAGS_INQ_REQ_TIMER_EXISTS;
	}

	afcd_create_check_date_sync_timer(info);

	AFC_EXIT();
}

/* Callback function to check the date sync */
static void
afcd_check_date_sync_timer_cb(bcm_usched_handle *hdl, void *arg)
{
	int ret = AFCE_OK;
	afcd_info_t *info = (afcd_info_t*)arg;
	afcd_check_date_sync_t *date_check = info->check_date_sync;
	time_t cur_time;
	double diffsecs = 0;
	AFC_ENTER();

	AFC_INFO("Timer callback to check date sync\n");

	cur_time = time(NULL);
	AFC_DEBUG("count %u cur_time %lu. prev_time %lu\n",
		date_check->count, (unsigned long)(cur_time),
		(unsigned long)(date_check->prev_time));

	/* If the count exceeds the maximum try, exit from the function */
	if (date_check->count > AFC_DEFAULT_NTP_DATE_CHECK_MAX_COUNT) {
		AFC_INFO("Current count %u exceeds maximum try %u\n", date_check->count,
			AFC_DEFAULT_NTP_DATE_CHECK_MAX_COUNT);
		free(date_check);
		info->check_date_sync = NULL;
		goto end;
	}

	/* Increment the count and check the previous and current date difference */
	date_check->count++;
	diffsecs = difftime(cur_time, date_check->prev_time);
	diffsecs = fabs(diffsecs);
	AFC_DEBUG("fabs(diffsecs) %.2f\n", diffsecs);
	/* If there is a huge difference in the time(more than 10 minutes), update the driver. */
	if (diffsecs > (AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT * 2)) {
		AFC_INFO("Difference between current time %lu and previous time %lu is %.2f which "
			"is greater than %u. So update the driver again\n",
			(unsigned long)(cur_time), (unsigned long)(date_check->prev_time), diffsecs,
			(AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT * 2));
		/* Read Available Spectrum Inquiry Response from file and store it in a structure */
		ret = afc_read_available_spectrum_inquiry_response_from_file(
			&info->spec_inq_resp_msg);
		if (ret != AFCE_OK) {
			info->spec_inq_resp_msg.flags |= AFC_RESP_FLAGS_RESP_EXPIRED;
			AFC_INFO("Failed to Read Available Spectrum Inquiry Response from file. "
				"Error[%s]\n", afcerrorstr(ret));
		} else {
			AFC_INFO("Successfully Read Available Spectrum Inquiry Response from "
				"file\n");
		}
	} else {
		AFC_INFO("Difference between current time %lu and previous time %lu is %.2f which "
			"is less than %u\n",
			(unsigned long)(cur_time), (unsigned long)(date_check->prev_time), diffsecs,
			(AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT * 2));
	}

	afcd_remove_timers(info->usched_hdl, afcd_check_date_sync_timer_cb, info);

	date_check->prev_time = cur_time;
	ret = afcd_add_timers(info->usched_hdl, info,
		AFCD_SEC_MICROSEC(AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT),
		afcd_check_date_sync_timer_cb, 0);

end:
	if ((ret != AFCE_OK) && info->check_date_sync) {
		free(info->check_date_sync);
		info->check_date_sync = NULL;
	}
	AFC_EXIT();
}

/* Create timer to check the date sync. This is required because the NTP date update may take
 * some time and the expiry time in driver might differ when the date gets updated. So, the idea
 * is to check the date every 5 minutes once for 5 times. If there is any huge difference in date,
 * read the Available Spectrum Inquiry Response and update the driver
 */
static void
afcd_create_check_date_sync_timer(afcd_info_t *info)
{
	int ret = AFCE_OK;
	afcd_check_date_sync_t *date_check = NULL;
	AFC_ENTER();

	AFC_INFO("Create timer to check date sync in %u seconds\n",
		AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT);

	/* If the timer is already present remove it */
	if (info->check_date_sync) {
		afcd_remove_timers(info->usched_hdl, afcd_check_date_sync_timer_cb, info);
		free(info->check_date_sync);
		info->check_date_sync = NULL;
	}

	date_check = (afcd_check_date_sync_t*)afc_malloc(sizeof(*date_check), NULL);
	if (date_check == NULL) {
		AFC_ERROR("Failed to allocate memory\n");
		goto end;
	}

	date_check->prev_time = time(NULL);
	info->check_date_sync = date_check;

	ret = afcd_add_timers(info->usched_hdl, info,
		AFCD_SEC_MICROSEC(AFC_DEFAULT_NTP_DATE_CHECK_TIMEOUT),
		afcd_check_date_sync_timer_cb, 0);

end:
	if ((ret != AFCE_OK) && info->check_date_sync) {
		free(info->check_date_sync);
		info->check_date_sync = NULL;
	}
	AFC_EXIT();
}

/* Updates location req msg flags based on afcd state. Creates timer for location request when
 * observed sp gain is either none or unsatisfactory.
 */
static void
afcd_next_action_on_state_change(afcd_info_t *info)
{
	AFC_ENTER();

	switch (info->state) {
		/* Intentional fall-through */
		case AFCD_BOOTUP:
		case AFCD_KNOWN_LOCATION_UNKNOWN_SP_GAIN:
		case AFCD_SATIATED:
			info->spec_inq_req_msg.flags |= AFC_REQ_FLAG_USE_CACHED;
			info->spec_inq_req_msg.flags &= ~AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS;
			break;

		/* Intentional fall-through */
		case AFCD_KNOWN_LOCATION_NO_SP_GAIN:
		case AFCD_KNOWN_LOCATION_UNSATISFACTORY_SP_GAIN:
			if (afcd_is_any_location_evaluation_pending(&info->spec_inq_req_msg)) {
				AFC_INFO("SP gain is 0 or unsatisfatory and there is still "
					"location evaluation is pending hence performing "
					"spectrum inquiry\n");
				if (afcd_perform_available_spectrum_inquiry_req(info) != AFCE_OK) {
					info->spec_inq_req_msg.flags &=
						~AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS;
				}
			} else {
				info->spec_inq_req_msg.flags &= ~(AFC_REQ_FLAG_USE_CACHED |
						AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS);
				afcd_create_inquiry_request_timer(info, TRUE);
			}
			break;

		default:
			assert(0);
			break;
	}

	AFC_EXIT();
}

/* Callback function to check sp gain */
static void
afcd_check_sp_gain_timer_cb(bcm_usched_handle *hdl, void *arg)
{
	afcd_info_t *info = (afcd_info_t*)arg;
	int ret;

	AFC_ENTER();

	info->state = AFCD_KNOWN_LOCATION_UNSATISFACTORY_SP_GAIN;
	AFC_INFO("AFCD state is %d \n", info->state);

	if ((ret = afc_check_txpwr_max()) >= 0) {
		info->state = AFCD_SATIATED;
	}
	AFC_INFO("AFCD state updated to %d \n", info->state);

	afcd_next_action_on_state_change(info);

	AFC_EXIT();
}

/* Create timer to check for the sp gain after configuring the wl with afc response */
static int
afcd_create_sp_gain_check_timer(afcd_info_t *info)
{
	int ret;

	AFC_ENTER();

	afcd_remove_timers(info->usched_hdl, afcd_check_sp_gain_timer_cb, info);

	ret = afcd_add_timers(info->usched_hdl, info,
			AFCD_SEC_MICROSEC(AFC_DEFAULT_SP_GAIN_CHECK_TIMEOUT),
			afcd_check_sp_gain_timer_cb, 0);

	if (ret != AFCE_OK) {
		AFC_ERROR("Failed to create sp gain check timer resetting afc request's location "
				"use in progress flag\n");
		info->spec_inq_req_msg.flags &= ~AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS;
	}

	AFC_EXIT();

	return ret;
}

int
main(int argc, char *argv[])
{
	int ret, mode, i;
	uint16 cmd = 0;
	uint32 msglevel;
	BCM_USCHED_STATUS status = BCM_USCHEDE_OK;

	/* helps know if the process is being started or restarted repeatedly */
	printf("\nAFCD (afc-daemon / web-client) PID: %ld, PPID: %ld :",
			(long)getpid(), (long)getppid());
	for (i = 0; i < argc; ++i) {
		printf(" %s", argv[i]);
	}
	printf("\n\n");

	/* Parse common cli arguments and daemonizes conditionally */
	cmd = afcd_parse_cli_args(argc, argv);

	/* Get NVRAM : Debug Message Level */
	msglevel = (uint32)afc_nvram_safe_get_int(NULL, AFC_NVRAM_MSGLEVEL, AFC_DEBUG_DEFAULT);
	afc_set_msglevel(msglevel);

	mode = afc_nvram_safe_get_int(NULL, AFCD_NVRAM_MODE, AFCD_DEF_MODE);
	AFC_DEBUG("AFCD Mode %d\n", mode);
	/* AFCD is not enabled */
	if (mode == AFCD_MODE_DISABLED) {
		AFC_WARNING("AFCD mode (%d) is disabled...\n", mode);
		goto end;
	}

	sleep(4); // allow other router daemons to boot up before making any requests

	/* Allocate & Initialize the info structure */
	g_afcdinfo = afcd_info_init(&ret, mode);
	AFC_ASSERT_MSG("afcd_info_init failed: %d\n", ret); /* returns in absence of 6GHz ifaces */

	/* Provide necessary info to debug_monitor for service restart */
	dm_register_app_restart_info(getpid(), argc, argv, NULL);

	/* Enable signal handlers */
	signal(SIGUSR2, afcd_signal_hdlr);

	g_afcdinfo->locpold_fd = afcd_open_and_add_locpold_sock_to_schedule();

	if (cmd & AFCD_CMD_FLAG_TEST_REQ) {
		/* Read the Available Spectrum Inquiry Request entries and store it in structure */
		(void)afc_read_available_spectrum_inquiry_request(&g_afcdinfo->request_id,
			g_afcdinfo->locpold_fd, &g_afcdinfo->spec_inq_req_msg);
	}

	if (cmd & AFCD_CMD_FLAG_FULL_OP) {
		(void)afc_read_available_spectrum_inquiry_request(&g_afcdinfo->request_id,
			g_afcdinfo->locpold_fd, &g_afcdinfo->spec_inq_req_msg);
	}

	if (cmd & AFCD_CMD_FLAG_TEST_RESP) {
		afcd_test_parse_json_response();
	}

	if (g_afcdinfo->mode == AFCD_MODE_PROXY) {
		uint32 nv_proxy_lag = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_PROXY_LAG,
				AFC_DEF_PROXY_LAG);
		/* delay first proxy mode request to let the repeater assoc/sync with the root AP */
		if (nv_proxy_lag) {
			AFC_INFO("Delaying first proxy mode request by %u seconds\n", nv_proxy_lag);
			sleep(nv_proxy_lag);
		}
	}

	if (AFC_RESP_IS_RESP_EXPIRED(g_afcdinfo->spec_inq_resp_msg.flags)) {
		AFC_INFO("Available Spectrum Inquiry Response is expired. Get fresh one\n");
		ret = afc_read_available_spectrum_inquiry_request(&g_afcdinfo->request_id,
			g_afcdinfo->locpold_fd, &g_afcdinfo->spec_inq_req_msg);
	}

	if (!AFCD_IS_INQ_REQ_TIMER_EXISTS(g_afcdinfo->flags)) {
		/* Create timer to perform the next Available Spectrum Inquiry Request */
		afcd_create_inquiry_request_timer(g_afcdinfo, FALSE);
	}

	AFC_INFO("Scheduler going to run\n");
	status = bcm_usched_run(g_afcdinfo->usched_hdl);
	AFC_WARNING("Return Code %d and Message : %s\n", status, bcm_usched_strerror(status));

end:
	/* Exit AFC */
	afcd_exit(g_afcdinfo);
	AFC_DEBUG("Exited AFC daemon...\n");

	return 0;
}
