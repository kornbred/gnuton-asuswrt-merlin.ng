/*
 * AFC Daemon Header
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
 * $Id: afcd.h 832722 2023-11-12 00:09:11Z $
 */

#ifndef _AFCD_H_
#define _AFCD_H_

#include "afc.h"
#include "bcm_usched.h"

#define AFCD_SEC_MICROSEC(x) ((unsigned long long)(x) * 1000 * 1000)

#define AFCD_CMD_FLAG_FOREGROUND	0x0001	/* Run the exe in foreground do not daemonize */
#define AFCD_CMD_FLAG_TEST_REQ		0x0002	/* Test JSON data creation from structure */
#define AFCD_CMD_FLAG_TEST_RESP		0x0004	/* Test Parsing JSON Response data from file */
#define AFCD_CMD_FLAG_FULL_OP		0x0008	/* Create JSON data send it to server and parse
						 * response
						 */

#define AFCD_MODE_DISABLED		0u	/* AFCD is disabled */
#define AFCD_MODE_ENABLED		1u	/* AFCD is enabled */
#define AFCD_MODE_PROXY			2u	/* AFCD working as proxy. Here it will not contact
						 * the server directly instead it will use CLI to
						 * talk to SmartMesh
						 */

/* AFCD NVRAM Default values */
#define AFCD_DEF_MODE		AFCD_MODE_DISABLED

/* AFCD NVRAMs */
#define AFCD_NVRAM_MODE		"afcd_mode"

/* Structure to hold the count and previous time to check the date sync */
typedef struct afcd_check_date_sync {
	uint8 count;		/* Number of times the timer is repeated */
	time_t prev_time;	/* Time at which the timer has created */
} afcd_check_date_sync_t;

/* AFC Daemon Bit flags for afc_info structure. */
#define AFCD_INFO_FLAGS_INQ_REQ_TIMER_EXISTS	0x0001	/* Available Spectrum Inquiry Request
							 * timer exists
							 */

/* Check whether the Available Spectrum Inquiry Request exists */
#define AFCD_IS_INQ_REQ_TIMER_EXISTS(flags)	((flags) & (AFCD_INFO_FLAGS_INQ_REQ_TIMER_EXISTS))

/* afcd states */
enum afcd_state {
	AFCD_BOOTUP = 0,
	AFCD_KNOWN_LOCATION_UNKNOWN_SP_GAIN = 1,
	AFCD_KNOWN_LOCATION_NO_SP_GAIN = 2,
	AFCD_KNOWN_LOCATION_UNSATISFACTORY_SP_GAIN = 3,
	AFCD_SATIATED = 4
};

/* Main AFC Common Application structure to store module info */
typedef struct afcd_info {
	uint8 mode;					/* AFC Daemon mode of type AFCD_MODE_XXX */
	uint32 flags;					/* Flags of tyep AFC_INFO_FLAGS_XXX */
	uint32 request_id;				/* Unique ID to identify an instance of an
							 * Available Spectrum Inquiry request
							 */
	bcm_usched_handle *usched_hdl;			/* Handle to Micro Scheduler Module */
	int cli_server_fd;				/* Socket FD of (CLI) Command Line
							 * Interface Server
							 */
	afcd_check_date_sync_t *check_date_sync;	/* Check date sync info */
	avl_spec_inq_req_msg_t spec_inq_req_msg;	/* Available Spectrum Inquiry Request
							 * message
							 */
	afc_avl_spec_inq_resp_msg_t spec_inq_resp_msg;	/* Available Spectrum Inquiry Response
							 * message
							 */
	uint32 web_req_gap;				/* gap in secs between two web requets */
	std_out_err_t std_out_err;			/* to redirect/restore stdout, stderr */
	int locpold_fd;                                 /* Socket FD to locpold */
	enum afcd_state state;				/* State w.r.t location and afc response */
} afcd_info_t;

/* Get Application module info */
afcd_info_t* afcd_get_ginfo();

#endif /* _AFCD_H_ */
