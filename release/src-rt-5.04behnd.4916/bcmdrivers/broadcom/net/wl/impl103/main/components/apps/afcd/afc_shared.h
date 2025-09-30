/*
 * AFC Private header file
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
 * $Id: afc_shared.h 832722 2023-11-12 00:09:11Z $
 */

#ifndef _AFC_SHARED_H_
#define _AFC_SHARED_H_
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <typedefs.h>
#include <bcmutils.h>
#include <time.h>
#include <sys/time.h>
#include <wlutils.h>

#ifndef ABS
#define	ABS(a)			(((a) < 0) ? -(a) : (a))
#endif /* ABS */

#ifndef ARRAYSIZE
#define ARRAYSIZE(a)		(sizeof(a) / sizeof(a[0]))
#endif

#define AFC_MAX_INQ_REQ_TIMEOUT	(24 * 60 * 60)	/* Maximum timeout of inquiry response */
#define AFC_TIMEOUT_ADVANCE	(1 * 60 * 60)	/* Request again these many seconds before expiry */
#define AFC_HEADER		"content-type: application/json"
#define AFC_HTTP_VERSION	CURL_HTTP_VERSION_1_1

#define REQUEST_JSON_FILENAME	"/tmp/afc_request.json"
#define RESPONSE_JSON_FILENAME	"/tmp/afc_response.json"

/* Available Spectrum Inquiry Request message */
#define AFC_METHOD_AVAILABLE_SPECTRUM_INQUIRY	"availableSpectrumInquiry"
/* Standalone Vendor Extension message optionally defined by vendor(s).
 * Vendor specific version if it exists, may be indicated in this message
 */
#define AFC_METHOD_VENDOR_EXTENSIONS		"vendorExtensions"

#define AFCE_OK			0	/* Success */
#define AFCE_FAIL		-1	/* General Failure */
#define AFCE_MALLOC		-2	/* Memory allocation failure */
#define AFCE_INV_ARG		-3	/* Invalid arguments */
#define AFCE_DTCURR		-4	/* Data Corrucpted */
#define AFCE_JSON_NULL_OBJ	-5	/* JSON Object NULL */
#define AFCE_JSON_INV_TAG_VAL	-6	/* Invalid TAG value */
#define AFCE_SOCKET		-7	/* Socket Error */
#define AFCE_USCHED_ERROR	-8	/* Micro-scheduler error */
#define AFCE_CURL		-9	/* Curl Error */
#define AFCE_NO_STORED_RES	-10	/* Stored Available Spectrum Inquiry Response not found */
#define AFCE_FILE_NOT_EXIST	-11	/* File not exists */
#define AFCE_USCHED_TIMER_EXIST	-12	/* usched timer already running */
#define AFCE_NO_GEOLOC		-13	/* Incomplete / No GeoLoc information available */
#define AFCE_INV_CLI_PASS_REQ	-14	/* Invalid CLI command in Proxy Mode to Pass AFC Request */
#define AFCE_INV_CLI_PASS_RESP	-15	/* Invalid CLI command to Pass AFC Response */
#define AFCE_NVRAM_GEOLOC	-16	/* Nvram stored geolocation used */
#define AFCE_LAST		AFCE_NVRAM_GEOLOC	/* Change this if there is any addition
							 * to new error codes
							 */

#define AFCE_STRLEN		128	/* Max string length for BCM errors */
#define VALID_AFCERROR(e)	((e <= 0) && (e >= AFCE_LAST))

/* These are collection of AFCE Error strings */
#define AFCERRSTRINGTABLE {			\
	"Success",				\
	"Failure",				\
	"Memory allocation failure",		\
	"Invalid arguments",			\
	"Data Corrucpted",			\
	"JSON Object NULL",			\
	"Invalid TAG value",			\
	"Socket Error",				\
	"Micro-scheduler error",		\
	"Curl Error",				\
	"Stored Available Spectrum Inquiry Response not found",	\
	"File not exists",			\
	"usched timer already running",		\
	"Geo-location info missing/incorrect",	\
	"Invalid CLI command in Proxy Mode to Pass AFC Request",	\
	"Invalid CLI command to Pass AFC Response",	\
	"Geolocation is being used from NVRAM",	\
}

#define AFC_ASSERT() \
		do { \
			if (ret != AFCE_OK) { \
				AFC_WARNING("AFC_ASSERT !!! ret=%d\n", ret); \
				goto end; \
			} \
		} while (0)

#define AFC_ASSERT_MSG(fmt, arg...) \
		do { \
			if (ret != AFCE_OK) { \
				AFC_WARNING(fmt, ##arg); \
				goto end; \
			} \
		} while (0)

#define AFC_ASSERT_ARG(arg, ERR) \
		do { \
			if (!arg) { \
				ret = ERR; \
				AFC_WARNING("%s\n", afcerrorstr(ret)); \
				goto end; \
			} \
		} while (0)

extern uint32 g_afc_msglevel;

#define AFC_DEBUG_ERROR		0x0001
#define AFC_DEBUG_WARNING	0x0002
#define AFC_DEBUG_INFO		0x0004
#define AFC_DEBUG_DETAIL	0x0008
#define AFC_DEBUG_TRACE		0x0010
#define AFC_DEBUG_DEFAULT	AFC_DEBUG_ERROR

#define AFC_PRINTF	printf

#define AFC_DIR_PRINT(fmt, arg...) \
	printf("AFC-DUMP >> (%lu) %s(%d): "fmt, (unsigned long)time(NULL), \
		__FUNCTION__, __LINE__, ##arg)

#define AFC_PRINT(prefix, fmt, arg...) \
	printf(prefix"AFC-%s >> (%lu) %s(%d): "fmt, AFC_MODULE, (unsigned long)time(NULL), \
		__FUNCTION__, __LINE__, ##arg)

#define AFC_ERROR(fmt, arg...) \
	if (g_afc_msglevel & AFC_DEBUG_ERROR) \
		AFC_PRINT("Err: ", fmt, ##arg)

#define AFC_WARNING(fmt, arg...) \
	if (g_afc_msglevel & AFC_DEBUG_WARNING) \
		AFC_PRINT("Warn: ", fmt, ##arg)

#define AFC_INFO(fmt, arg...) \
	if (g_afc_msglevel & AFC_DEBUG_INFO) \
		AFC_PRINT("Info: ", fmt, ##arg)

#define AFC_DEBUG(fmt, arg...) \
	if (g_afc_msglevel & AFC_DEBUG_DETAIL) \
		AFC_PRINT("Dbg: ", fmt, ##arg)

#define AFC_TRACE(fmt, arg...) \
	if (g_afc_msglevel & AFC_DEBUG_TRACE) \
		AFC_PRINT("Trace: ", fmt, ##arg)

#define AFC_ENTER()	AFC_TRACE("Enter...\n")
#define AFC_EXIT()	AFC_TRACE("Exit...\n")

#define AFC_IS_DEBUG()	(g_afc_msglevel & AFC_DEBUG_DETAIL)
#define AFC_IS_INFO()	(g_afc_msglevel & AFC_DEBUG_INFO)

#define AFC_SNPRINTF(str, sz, arg...) ({ int ret = 0; \
	if ((ret = snprintf(str, sz, ##arg)) >= (sz)) { str[(sz) - 1] = '\0'; ret = (sz); } ret; })

#endif /* _AFC_SHARED_H_ */
