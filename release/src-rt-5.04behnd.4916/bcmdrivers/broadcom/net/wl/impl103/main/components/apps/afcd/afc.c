/*
 * AFC Library
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
 * $Id: afc.c 836713 2024-02-20 04:59:42Z $
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <curl/curl.h>
#include <signal.h>
#include <errno.h>
#include <bcmnvram.h>
#include <bcmwifi_channels.h>
#include <bcmwifi_rclass.h>
#include "shutils.h"

#include <sys/un.h>

#include <locpol_ipc_cmn.h>
#include <locpol_ipc_ad.h>
#include <locpol_types.h>
#include <locpol_keys.h>

#include "afc.h"
#include "afc_shared.h"

uint32 g_afc_msglevel = AFC_DEBUG_DEFAULT;
#define AFC_MODULE	"LIB"

bool afc_swap = FALSE;	/* find dongle endianness and store if h2d / d2h macros need to swap */

uint8 g_afc_num_ifnames;				/* Number of entries in ifnames array */
char g_afc_ifnames[AFCD_MAX_IFACE][IFNAMSIZ];		/* List of 6GHz interfaces */

/* Cleanup Available Spectrum Inquiry request object */
static void afc_cleanup_spectrum_inquiry_request_object(avl_spec_inq_req_t *spec_inq_req);

/* initialize global afc_swap variable that is used to decide if dtoh/htod macros need to swap */
int
afc_init_swap(char *ifname)
{
	int ret, val;

	if ((ret = wl_ioctl(ifname, WLC_GET_MAGIC, &val, sizeof(int))) < 0) {
		return ret;
	}

	/* check if IOCTL swapping is necessary */
	if (val == (int)bcmswap32(WLC_IOCTL_MAGIC)) {
		val = bcmswap32(val);
		afc_swap = TRUE;
	}
	if (val != WLC_IOCTL_MAGIC) {
		return AFCE_FAIL;
	}

	return AFCE_OK;
}

/* Initialize generic list */
void
afc_glist_init(afc_glist_t *list)
{
	list->count = 0;
	dll_init(&(list->head));
}

/* Append a node to generic list */
void
afc_glist_append(afc_glist_t *list, dll_t *new_obj)
{
	dll_append((dll_t *)&(list->head), new_obj);
	++(list->count);
}

/* Prepend a node to generic list */
void
afc_glist_prepend(afc_glist_t *list, dll_t *new_obj)
{
	dll_prepend((dll_t *)&(list->head), new_obj);
	++(list->count);
}

/* Delete a node from generic list */
void
afc_glist_delete(afc_glist_t *list, dll_t *obj)
{
	dll_delete(obj);
	--(list->count);
}

/* Delete all the node from generic list */
int
afc_glist_cleanup(afc_glist_t *list)
{
	int ret = AFCE_OK;
	dll_t *item_p, *next_p;
	AFC_ENTER();

	/* Validate arg */
	AFC_ASSERT_ARG(list, AFCE_INV_ARG);

	if (list->count == 0) {
		goto end;
	}

	/* Travese List */
	foreach_safe_glist_item(item_p, (*list), next_p) {

		/* need to keep next item incase we remove node in between */
		next_p = dll_next_p(item_p);

		/* Remove item itself from list */
		afc_glist_delete(list, item_p);
		free(item_p);
	}

	/* Sanity Check */
	if (list->count) {
		AFC_WARNING("Error: List count [%d] after cleanup\n", list->count);
		ret = AFCE_DTCURR;
	}

end:
	AFC_EXIT();
	return ret;

}

/* Read data from file. Returns number of elements read. Total size read will be
 * read_elements * (*size)
 */
size_t
afc_read_file(char *filepath, char **data, size_t *size)
{
	FILE *file = NULL;
	size_t read_elements = 0;
	AFC_ENTER();

	if (size) {
		*size = 0;
	}
	if (!filepath || !data || !size) {
		AFC_ERROR("One of the input args is NULL\n");
		AFC_EXIT();
		return 0;
	}

	/* Open the file */
	file = fopen(filepath, "rb");
	if (!file) {
		AFC_ERROR("Failed to open the file %s\n", filepath);
		goto end;
	}

	/* Get the length of the file */
	fseek(file, 0, SEEK_END);
	*size = ftell(file);
	fseek(file, 0, SEEK_SET);
	(*size)++;

	*data = (char*)calloc(*size, sizeof(char));
	if (*data == NULL) {
		goto end;
	}

	/* Read from the file */
	read_elements = fread(*data, ((*size) - 1), 1, file);
	(*data)[(*size) - 1] = '\0';

end:
	if (file) {
		fclose(file);
	}
	AFC_EXIT();
	return read_elements;
}

/* Write content to file */
void
afc_write_to_file(char *filepath, char *data, size_t size)
{
	FILE *fp = NULL;
	AFC_ENTER();

	if (!filepath || !data || !size) {
		AFC_ERROR("One of the input args is NULL or 0\n");
		goto end;
	}

	fp = fopen(filepath, "w");
	if (fp == NULL) {
		AFC_ERROR("Error in creating the file %s\n", filepath);
		goto end;
	}
	/* Write the buffer in file */
	fwrite(data, sizeof(data[0]), size, fp);
	/* close the file */
	fclose(fp);

end:
	AFC_EXIT();
}

/* Set the message level */
void
afc_set_msglevel(uint32 msglevel)
{
	AFC_ENTER();

	g_afc_msglevel = msglevel;

	AFC_EXIT();
}

static char afc_undeferrstr[32];
static const char *afcerrorstrtable[] = AFCERRSTRINGTABLE;

/* Convert the error codes into related error strings  */
const char *
afcerrorstr(int afcerror)
{
	/* check if someone added a afcerror code but forgot to add errorstring */
	assert(ABS(AFCE_LAST) == (ARRAYSIZE(afcerrorstrtable) - 1));

	/* check if afcerror is valid */
	if (afcerror > 0 || afcerror < AFCE_LAST) {
		snprintf(afc_undeferrstr, sizeof(afc_undeferrstr), "Undefined error %d", afcerror);
		return afc_undeferrstr;
	}

	/* check if someone added a errorstring longer than allowed */
	assert(strlen(afcerrorstrtable[-afcerror]) < AFCE_STRLEN);

	return afcerrorstrtable[-afcerror];
}

/* Generic memory Allocation function for AFC app */
void*
afc_malloc(uint32 len, int *error)
{
	int ret = -1;
	void* pbuffer = NULL;
	AFC_ENTER();

	if (len <= 0) {
		goto end;
	}

	pbuffer = calloc(1, len);
	if (pbuffer == NULL) {
		goto end;
	} else {
		ret = AFCE_OK;
	}

end:
	if (ret != AFCE_OK) {
		AFC_ERROR("Failed to allocate %u bytes\n", len);
	}
	if (error) {
		*error = ret;
	}

	AFC_EXIT();
	return pbuffer;
}

/* Callback function to store the curl response */
static size_t
afc_store_curl_output_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
	size_t realsize = size * nmemb;
	afc_curl_output_t *mem = (afc_curl_output_t *)userp;
	AFC_ENTER();

	char *ptr = realloc(mem->data, mem->size + realsize + 1);
	if (!ptr) {
		/* out of memory! */
		AFC_ERROR("not enough memory (realloc returned NULL)\n");
		return 0;
	}

	mem->data = ptr;
	memcpy(&(mem->data[mem->size]), contents, realsize);
	mem->size += realsize;
	mem->data[mem->size] = 0;

	AFC_EXIT();
	return realsize;
}

/* Definitions to allow insecure, robust curl. Relevant to the following function only */
#define AFC_INSECURE_ENABLE			0x0001
#define AFC_INSECURE_NO_VERIFYPEER		0x0002
#define AFC_INSECURE_NO_VERIFYHOST		0x0004

#define AFC_ROBUST_ENABLE			0x0001
#define AFC_ROBUST_VERIFYSTATUS			0x0002

/* Post HTTPS request */
int
afc_curl_send_request(avl_spec_inq_req_msg_t *spec_inq_req_msg, char *data,
	char *method, afc_curl_output_t *output)
{
	int ret = AFCE_CURL, nv_insecure, nv_robust;
	CURL *curl = NULL;
	CURLcode res;
	struct curl_slist *list = NULL;
	char afc_url[AFC_MAX_URL]; /* max URL length */
	AFC_ENTER();

	AFC_INFO("POST JSON data to AFC System\n");

	res = curl_global_init(CURL_GLOBAL_DEFAULT);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_global_init() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	curl = curl_easy_init();
	if (!curl) {
		AFC_ERROR("curl_easy_init() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* to help override libcurl defaults to remove security */
	nv_insecure = (int32) afc_nvram_safe_get_int(NULL, AFC_NVRAM_INSECURE,
		AFC_DEF_INSECURE);
	AFC_INFO("nv_insecure: %d or 0x%04x\n", nv_insecure, nv_insecure);

	/* to help override libcurl defaults to add more security robustness */
	nv_robust = (int32) afc_nvram_safe_get_int(NULL, AFC_NVRAM_ROBUST,
		AFC_DEF_ROBUST);
	AFC_INFO("nv_robust: %d or 0x%04x\n", nv_robust, nv_robust);

	/* Format: $BASE_URL/ $METHOD */
	snprintf(afc_url, sizeof(afc_url), "%s/%s", spec_inq_req_msg->base_url,
		spec_inq_req_msg->method);
	res = curl_easy_setopt(curl, CURLOPT_URL, afc_url);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* HTTP version number shall be 1.1 */
	res = curl_easy_setopt(curl, CURLOPT_HTTP_VERSION, AFC_HTTP_VERSION);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* time in seconds that the libcurl transfer operation to take */
	res = curl_easy_setopt(curl, CURLOPT_TIMEOUT, spec_inq_req_msg->curl_wait_timeout);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* TLS version 1.2 or later */
	res = curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	if (nv_insecure == AFC_INSECURE_ENABLE || (nv_insecure & AFC_INSECURE_NO_VERIFYPEER) != 0) {
		 /* Disables verification through trusted CA in /etc and nvram afc_tls_ca_cert */
		res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
		if (res != CURLE_OK) {
			AFC_ERROR("curl_easy_setopt() verify peer 0 failed. Error Desc: %s\n",
				curl_easy_strerror(res));
			goto end;
		}
		AFC_INFO("Disabled CURLOPT_SSL_VERIFYPEER\n");
	}
	if (nv_insecure == AFC_INSECURE_ENABLE || (nv_insecure & AFC_INSECURE_NO_VERIFYHOST) != 0) {
		res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
		if (res != CURLE_OK) {
			AFC_ERROR("curl_easy_setopt() verify host 0 failed. Error Desc: %s\n",
				curl_easy_strerror(res));
			goto end;
		}
		AFC_INFO("Disabled CURLOPT_SSL_VERIFYHOST\n");
	}

	if (nv_robust == AFC_ROBUST_ENABLE || (nv_robust & AFC_ROBUST_VERIFYSTATUS) != 0) {
		/* enables OCSP based certificate expiry/revocation verification */
		res = curl_easy_setopt(curl, CURLOPT_SSL_VERIFYSTATUS, 1L);
		if (res != CURLE_OK) {
			AFC_ERROR("curl_easy_setopt() verify status 1 failed. Error Desc: %s\n",
				curl_easy_strerror(res));
			goto end;
		}
		AFC_INFO("Enabled CURLOPT_SSL_VERIFYSTATUS\n");
	}

	if (spec_inq_req_msg->tls_cacert) {
		res = curl_easy_setopt(curl, CURLOPT_CAINFO, spec_inq_req_msg->tls_cacert);
		if (res != CURLE_OK) {
			AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n",
				curl_easy_strerror(res));
			goto end;
		}
	}

	if (spec_inq_req_msg->mtls_cert) {
		res = curl_easy_setopt(curl, CURLOPT_SSLCERT, spec_inq_req_msg->mtls_cert);
		if (res != CURLE_OK) {
			AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n",
				curl_easy_strerror(res));
			goto end;
		}
	}

	/* set our custom set of headers */
	list = curl_slist_append(list, AFC_HEADER);
	if (list == NULL) {
		AFC_ERROR("curl_slist_append() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	res = curl_easy_setopt(curl, CURLOPT_HTTPHEADER, list);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* HTTP POST method will be used for all requests from the AFC Device to
	 * the AFC System
	 */
	res = curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* send all data to this function  */
	res = curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, afc_store_curl_output_cb);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* we pass our 'chunk' struct to the callback function */
	res = curl_easy_setopt(curl, CURLOPT_WRITEDATA, (void *)output);
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n", curl_easy_strerror(res));
		goto end;
	}

	/* If debug is enabled, enable verbose mode */
	if (AFC_IS_DEBUG()) {
		res = curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
		if (res != CURLE_OK) {
			AFC_ERROR("curl_easy_setopt() failed. Error Desc: %s\n",
				curl_easy_strerror(res));
			goto end;
		}
	}

	/* Perform the request, res will get the return code */
	res = curl_easy_perform(curl);
	/* Check for errors */
	if (res != CURLE_OK) {
		AFC_ERROR("curl_easy_perform() failed. Error Desc: %s\n",
			curl_easy_strerror(res));
	} else {
		ret = 0;
		AFC_INFO("POST JSON data to AFC System successful got the response\n");
	}

end:
	if (list) {
		curl_slist_free_all(list); /* free the list again */
	}

	if (curl) {
		/* always cleanup */
		curl_easy_cleanup(curl);
	}

	curl_global_cleanup();

	AFC_EXIT();
	return ret;
}

/* Count the number of entries in a space seperated list */
int
afc_count_space_sep_list(char *list)
{
	int count = 0;
	char *next;
	char field[NVRAM_MAX_VALUE_LEN];

	foreach(field, list, next) {
		count++;
	}

	return count;
}

/* Read certification ID entries and store it structure */
static void
afc_read_certification_Id(afc_device_descriptor_t *dev_desc)
{
	int ret = AFCE_OK;
	afc_certification_Id_t *certificationId;
	AFC_ENTER();

	afc_glist_init(&dev_desc->certification_Id);

	certificationId = (afc_certification_Id_t*)afc_malloc(sizeof(*certificationId), &ret);
	AFC_ASSERT();

	snprintf(certificationId->rulesetId, sizeof(certificationId->rulesetId), "%s",
		afc_nvram_safe_get_def(AFC_NVRAM_REG_RULES, AFC_DEF_REG_RULES));
	snprintf(certificationId->id, sizeof(certificationId->id), "%s",
		afc_nvram_safe_get_def(AFC_NVRAM_CERT_ID, AFC_DEF_CERT_ID));

	AFC_DEBUG("certificationId rulesetId[%s] id[%s] \n",
		certificationId->rulesetId, certificationId->id);

	afc_glist_append(&dev_desc->certification_Id, (dll_t *)certificationId);

end:
	AFC_EXIT();
}

/* Read device description entries and store it in structure */
static void
afc_read_device_description(afc_device_descriptor_t *dev_desc)
{
	AFC_ENTER();

	snprintf(dev_desc->serial_number, sizeof(dev_desc->serial_number), "%s",
		afc_nvram_safe_get_def(AFC_NVRAM_DEV_SERIAL_NO, AFC_DEF_DEV_SERIAL_NO));

	afc_read_certification_Id(dev_desc);

	AFC_EXIT();
	return;
}

/* Read point entries and store it in structure */
static void
afc_read_point(afc_point_t *point)
{
	AFC_ENTER();
	point->longitude =
		afc_nvram_safe_get_double(NULL, AFC_NVRAM_GEO_LONGITUDE, AFC_DEF_LONGITUDE);
	point->latitude =
		afc_nvram_safe_get_double(NULL, AFC_NVRAM_GEO_LATITUDE, AFC_DEF_LATITUDE);
	AFC_DEBUG("Longitude of the AP[%.17g] Latitude of the AP[%.17g]\n",
		point->longitude, point->latitude);
	AFC_EXIT();
}

/* Read ellipse entries and store it in structure */
static void
afc_read_ellipse(afc_ellipse_t *ellipse)
{
	AFC_ENTER();

	afc_read_point(&ellipse->center);

	ellipse->major_axis = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_MAJOR_AXIS,
		AFC_DEF_MAJOR_AXIS);
	ellipse->minor_axis = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_MINOR_AXIS,
		AFC_DEF_MINOR_AXIS);
	ellipse->orientation = (float)afc_nvram_safe_get_double(NULL, AFC_NVRAM_ORIENTATION,
		AFC_DEF_ORIENTATION);
	AFC_DEBUG("Length of the major semi axis of an ellipse[%u] Length of the minor semi axis "
		"of an ellipse[%u] Orientation of the majorAxis field in decimal degrees[%.17g]\n",
		ellipse->major_axis, ellipse->minor_axis, ellipse->orientation);

	AFC_EXIT();
}

#ifdef AFC_TEST_LINEAR_POLYGON
/* Read Linear polygon entries and store it in structure */
static void
afc_read_linear_polygon(afc_location_t *location)
{
	int ret = AFCE_OK;
	afc_points_t *linear_polygon;
	AFC_ENTER();

	linear_polygon = (afc_points_t*)afc_malloc(sizeof(*linear_polygon), &ret);
	AFC_ASSERT();

	/* Read point object for linear polygon */
	afc_read_point(&linear_polygon->point);

	afc_glist_append(&location->linear_polygon, (dll_t *)linear_polygon);
end:
	AFC_EXIT();
}
#endif /* AFC_TEST_LINEAR_POLYGON */

#ifdef AFC_TEST_RADIAL_POLYGON
/* Read radial polygon entries and store it in structure */
static void
afc_read_radial_polygon(afc_radial_polygon_t *radial_polygon)
{
	int ret = AFCE_OK;
	afc_vectors_t *outer_boundary;
	AFC_ENTER();

	afc_glist_init(&radial_polygon->outer_boundary);

	/* Read point object for radial polygon */
	afc_read_point(&radial_polygon->center);

	outer_boundary = (afc_vectors_t*)afc_malloc(sizeof(*outer_boundary), &ret);
	AFC_ASSERT();

	outer_boundary->length = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_VECTOR_LEN,
		AFC_DEF_VECTOR_LEN);
	outer_boundary->angle = afc_nvram_safe_get_double(NULL, AFC_NVRAM_VECTOR_ANGLE,
		AFC_DEF_VECTOR_ANGLE);
	AFC_DEBUG("Distance in meters from a specified Point[%u] Direction of a vector in decimal "
		"degrees[%.17g]\n", outer_boundary->length, outer_boundary->angle);

	afc_glist_append(&radial_polygon->outer_boundary, (dll_t *)outer_boundary);
end:
	AFC_EXIT();
}
#endif /* AFC_TEST_RADIAL_POLYGON */

/* Read elevation entries and store it in structure */
static void
afc_read_elevation(afc_elevation_t *elevation)
{
	AFC_ENTER();

	elevation->height = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_LOC_HEIGHT,
		AFC_DEF_LOC_HEIGHT);
	snprintf(elevation->height_type, sizeof(elevation->height_type), "%s",
		afc_nvram_safe_get_def(AFC_NVRAM_LOC_HEIGHT_TYPE, AFC_DEF_LOC_HEIGHT_TYPE));
	elevation->vertical_uncertainty = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_LOC_VER_UNCERT,
		AFC_DEF_LOC_VER_UNCERT);
	AFC_DEBUG("Height of the AP antenna in meters Above Ground Level (AGL), as measured "
		"relative to local ground level[%u] height_type [%s] vertical distance above and "
		"below the value of the height field within which the AP is located[%u]\n",
		 elevation->height, elevation->height_type, elevation->vertical_uncertainty);

	AFC_EXIT();
}

/* Connect to the location policy daemon to request a geolocation fix.
 */
static int
afc_req_locpold(avl_spec_inq_req_msg_t *spec_inq_req_msg, int locpold_fd, uint32 *out_seq_no)
{
	static uint32 seq_no = 0;
	ipc_req_t req = {0};
	uint32 loc_req_timeout = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_LOC_REQ_TIMEOUT,
			AFC_DEF_LOC_REQ_TIMEOUT);

	if (loc_req_timeout < AFC_DEF_LOC_REQ_MIN_TIMEOUT) {
		loc_req_timeout = AFC_DEF_LOC_REQ_MIN_TIMEOUT;
	}

	/* Retry getting socket fd to locpold in case afcd fails to open it during init time */
	if (locpold_fd == -1) {
		if (spec_inq_req_msg->afc_get_lockpold_sock) {
			locpold_fd = spec_inq_req_msg->afc_get_lockpold_sock();
			if (locpold_fd == -1) {
				AFC_ERROR("Failed to open socket to locpold\n");
				return AFCE_SOCKET;
			}
		} else {
			AFC_ERROR("Invalid socket to locpold\n");
			return AFCE_SOCKET;
		}
	}

	// send request to locpold for geo-location
	req.hdr.msg_type = CMD_AD_LD_LOC_REQ;
	req.hdr.len = sizeof(req.req.location_req);
	req.hdr.seq_no = ++seq_no;
	req.hdr.timestamp = time(NULL);
	// Status field is unused for request
	req.req.location_req.timeout = loc_req_timeout;
	req.req.location_req.use_cached = AFC_REQ_IS_USE_CACHED_SET(spec_inq_req_msg->flags);
	// mobile client struct is unused here
	if (write(locpold_fd, (void *) &req, sizeof(req)) == -1) {
		AFC_ERROR("error: %s\n", strerror(errno));
		return AFCE_SOCKET;
	}
	*out_seq_no = req.hdr.seq_no;

	AFC_INFO("Request timestamp=%lld seq=%u timeout=%u use_cached=%u\n",
			(long long)req.hdr.timestamp, req.hdr.seq_no, loc_req_timeout,
			req.req.location_req.use_cached);

	return AFCE_OK;
}

/* Read location entries and store it in structure */
static int
afc_read_location(avl_spec_inq_req_msg_t *spec_inq_req_msg, int locpold_fd,
		afc_location_t *location, uint32 *seq_no)
{
	int ret = AFCE_OK, raw_mode;

	AFC_ENTER();

	raw_mode = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_READ_RAW_LOC, AFC_DEF_READ_RAW_LOC);
	AFC_INFO("nvram %s/raw_mode: %d\n", AFC_NVRAM_READ_RAW_LOC, raw_mode);

	afc_glist_init(&location->linear_polygon);

	/* Read geolocation from nvram in AFC_READ_RAW_LOC_ALWAYS mode or
	 * if mode is AFC_READ_RAW_ON_LOCPOL_ERR and locpold return error or
	 * if mode if AFC_READ_RAW_ON_INVALID_LOC and coordinates are bad.
	 */
	if (raw_mode == AFC_READ_RAW_LOC_ALWAYS ||
			((ret = afc_req_locpold(spec_inq_req_msg, locpold_fd, seq_no)) &&
			raw_mode == AFC_READ_RAW_ON_LOCPOL_ERR) ||
			(!AFC_CHECK_LOC(location) &&
			raw_mode == AFC_READ_RAW_ON_INVALID_LOC)) {
		AFC_INFO("Reading raw location from nvrams mode=%d ret=%d\n", raw_mode, ret);
		afc_read_ellipse(&location->ellipse);
		afc_read_elevation(&location->elevation);
		location->flags |= AFC_LOCATION_FLAG_VALID;
		ret = AFCE_NVRAM_GEOLOC;
	}

	location->indoor_deployment = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_LOC_DEPLOYMENT,
		AFC_DEF_LOC_DEPLOYMENT);
	AFC_DEBUG("Indoor or Outdoor deployment of the AP[%s]\n",
		((location->indoor_deployment == AFC_INDOOR_DEPLOYMENT_INDOOR) ? "Indoor" :
		((location->indoor_deployment == AFC_INDOOR_DEPLOYMENT_OUTDOOR) ?
		"Outdoor" : "Unknown")));

#ifdef AFC_TEST_LINEAR_POLYGON
	afc_read_linear_polygon(location);
#endif /* AFC_TEST_LINEAR_POLYGON */

#ifdef AFC_TEST_RADIAL_POLYGON
	afc_read_radial_polygon(&location->radial_polygon);
#endif /* AFC_TEST_RADIAL_POLYGON */

	AFC_EXIT();

	return ret;
}

/* Add frequnecy range to request */
static void
afc_add_frequency_range(avl_spec_inq_req_t *spec_inq_req, uint32 low_frequency,
	uint32 high_frequency)
{
	int ret = AFCE_OK;
	afc_freq_range_t *inq_freq_range;
	AFC_ENTER();

	inq_freq_range = (afc_freq_range_t*)afc_malloc(sizeof(*inq_freq_range), &ret);
	AFC_ASSERT();

	inq_freq_range->low_frequency = low_frequency;
	inq_freq_range->high_frequency = high_frequency;
	AFC_INFO("Frequency Range: Low Frequency[%u] High Frequency[%u]\n",
		inq_freq_range->low_frequency, inq_freq_range->high_frequency);

	afc_glist_append(&spec_inq_req->inq_freq_range, (dll_t *)inq_freq_range);
end:
	AFC_EXIT();
}

static bool
afc_is_cc_canada(char *ifname)
{
	char nv_cc[128], *cc;

	AFC_SNPRINTF(nv_cc, sizeof(nv_cc), "%s_country_code", ifname);
	nv_cc[sizeof(nv_cc) - 1] = '\0';
	cc = afc_nvram_safe_get(nv_cc);
	AFC_INFO("nvram %s: '%s'\n", nv_cc, cc);
	if (!strncmp(cc, "CA", MIN(strlen(cc), strlen("CA")))) {
		return TRUE;
	}

	return FALSE;
}

/* Read frequency range entries and store it in structure */
void
afc_read_frequency_range(avl_spec_inq_req_t *spec_inq_req)
{
	char *nvval, *save_ptr, *ptr;
	int idx = 0, fmin, fmax;

	AFC_ENTER();

	nvval = afc_nvram_safe_get_def(AFC_NVRAM_FREQ_RANGE, "");
	if (!nvval[0]) {
		if (g_afc_ifnames[0][0] && afc_is_cc_canada(g_afc_ifnames[0])) {
			AFC_PRINT("Info: ", "inquiry-by-freq for Canada\n");
			afc_add_frequency_range(spec_inq_req, 5925, 6875);	// UNII-5, 6 & 7
			goto end;
		}

		AFC_INFO("nvram %s is not set. Using defaults\n", AFC_NVRAM_FREQ_RANGE);
		afc_add_frequency_range(spec_inq_req, 5925, 5945);	// UNII-5 6g2
		afc_add_frequency_range(spec_inq_req, 5945, 6425);	// UNII-5 6g1   - 6g93
		afc_add_frequency_range(spec_inq_req, 6525, 6875);	// UNII-7 6g117 - 6g181
		/* current implementation / definition of AFC server throws error if
		 * inquiry by frequency is for a channel outside UNII-5 & 7.
		 * afc_add_frequency_range(spec_inq_req, 5925, 7125);	// UNII-5, 6, 7 & 8
		 */
		goto end;
	}

	AFC_INFO("nvram %s is set to \"%s\". Using defaults\n", AFC_NVRAM_FREQ_RANGE, nvval);
	fmin = wf_channel2mhz(CH_MIN_6G_CHANNEL + 1, WF_CHAN_FACTOR_6_G) - 10;	// left of 6g2
	fmax = wf_channel2mhz(CH_MAX_6G_CHANNEL, WF_CHAN_FACTOR_6_G) + 10;	// right of 6g233
	AFC_INFO("Expecting frequency ranges in %d to %d MHz (inclusive)\n", fmin, fmax);
	while ((ptr = strtok_r(idx ? NULL : nvval, ";", &save_ptr)) != NULL) {
		int fstart, fend;
		idx++;
		sscanf(ptr, "%d,%d", &fstart, &fend);
		if (fstart < fmin || fend > fmax || fstart >= fend) {
			AFC_WARNING("From nvram %s, skipping invalid range '%s' / [%d - %d]\n",
					AFC_NVRAM_FREQ_RANGE, ptr, fstart, fend);
			continue;
		}
		afc_add_frequency_range(spec_inq_req, fstart, fend);
	}

end:
	AFC_EXIT();
}

/* Read global operating class entries and store it in structure */
static void
afc_read_gclass(avl_spec_inq_req_t *spec_inq_req, uint8 opclass)
{
	uint8 idx;
	int ret = AFCE_OK, bcm_ret;
	afc_inq_chans_t *inq_chans;
	const bcmwifi_rclass_info_t *rcinfo;
	AFC_ENTER();

	bcm_ret = bcmwifi_rclass_get_rclass_info(BCMWIFI_RCLASS_TYPE_GBL, opclass, &rcinfo);
	if (bcm_ret != BCME_OK) {
		AFC_WARNING("Invalid Global Operating class %u specified\n", opclass);
		goto end;
	}

	/* Do not add if the Operating class is not 6G */
	if (rcinfo->band != BCMWIFI_BAND_6G) {
		AFC_WARNING("Global Operating class %u is not 6G\n", opclass);
		goto end;
	}

	inq_chans = (afc_inq_chans_t*)afc_malloc(sizeof(*inq_chans), &ret);
	AFC_ASSERT();

	inq_chans->opclass = rcinfo->rclass;
	AFC_INFO("Add opclass[%d]\n", inq_chans->opclass);

	/* No need to add the channel information(Just adding for testing). If no value is provided,
	 * the request is for spectrum availability for all center frequency indices for the given
	 * globalOperatingClass
	 */
	if (rcinfo->chan_set_len > 0) {

		inq_chans->chan_cfi_count = rcinfo->chan_set_len;
		inq_chans->chan_cfi =
			(uint8*)afc_malloc(inq_chans->chan_cfi_count * sizeof(uint8), &ret);
		AFC_ASSERT();

		for (idx = 0; idx < rcinfo->chan_set_len; idx++) {
			inq_chans->chan_cfi[idx] = rcinfo->chan_set[idx];
			AFC_DEBUG("Channel CFI %d for opclass %d\n",
				inq_chans->chan_cfi[idx], inq_chans->opclass);
		}
	}

	afc_glist_append(&spec_inq_req->inq_chans, (dll_t *)inq_chans);
end:
	AFC_EXIT();
}

/* Read inquired channels entries and store it in structure */
void
afc_read_inquired_channels(avl_spec_inq_req_t *spec_inq_req)
{
	char *nvval, *save_ptr, *ptr;
	int idx = 0;

	AFC_ENTER();

	nvval = afc_nvram_safe_get_def(AFC_NVRAM_OP_CLASS, "");

	if (!nvval[0]) {
		AFC_INFO("nvram %s is not set. Using defaults\n", AFC_NVRAM_OP_CLASS);
		afc_read_gclass(spec_inq_req, 131);
		afc_read_gclass(spec_inq_req, 132);
		afc_read_gclass(spec_inq_req, 133);
		afc_read_gclass(spec_inq_req, 134);
		// afc_read_gclass(spec_inq_req, 135); '80+'(80p80) is not supported in our products
		afc_read_gclass(spec_inq_req, 136);
		goto end;
	}

	AFC_INFO("nvram %s is set to \"%s\". Using defaults\n", AFC_NVRAM_OP_CLASS, nvval);
	while ((ptr = strtok_r(idx ? NULL : nvval, ",", &save_ptr)) != NULL) {
		int oc = (int)strtoul(ptr, NULL, 0);
		idx++;
		if (oc < 131 || oc > 137) {
			AFC_WARNING("From nvram %s, skipping invalid op_class %s/%d\n",
					AFC_NVRAM_OP_CLASS, ptr, oc);
			continue;
		}
		afc_read_gclass(spec_inq_req, oc);
	}

end:
	AFC_EXIT();
}

/* Get the new request ID for the Available Spectrum Inquiry Request */
static int
afc_get_new_request_id(avl_spec_inq_req_msg_t *spec_inq_req_msg,
	char *str_req_id, size_t str_req_id_sz, uint32 *request_id)
{
	uint32 out_request_id;
	int ret = AFCE_OK, req_id;
	AFC_ENTER();

	req_id = (int32)afc_nvram_safe_get_int(NULL, AFC_NVRAM_REQ_ID, AFC_DEF_REQ_ID);
	if (req_id != AFC_DEF_REQ_ID) {
		out_request_id = req_id;
	} else {
		out_request_id = ++(*request_id);
	}

	/* For making request ID unique per device, combine it with the IEEE1905 AL MAC if
	 * present
	 */
	if (!ETHER_ISNULLADDR(&spec_inq_req_msg->al_mac)) {
		snprintf(str_req_id, str_req_id_sz, "%02X%02X%02X%02X%02X%02X%u",
			ETHER_TO_MACF(spec_inq_req_msg->al_mac), out_request_id);
	} else {
		snprintf(str_req_id, str_req_id_sz, "%u", out_request_id);
	}
	AFC_INFO("New request ID %s\n", str_req_id);

	AFC_EXIT();
	return ret;
}

/* Read Available Spectrum Inquiry Request entries and store it in structure */
int
afc_read_available_spectrum_inquiry_request(uint32 *request_id, int locpold_fd,
	avl_spec_inq_req_msg_t *spec_inq_req_msg)
{
	int ret = AFCE_OK;
	avl_spec_inq_req_t *spec_inq_req = NULL;
	char *nvval;
	AFC_ENTER();

	AFC_INFO("Read Available Spectrum Inquiry Request entries\n");

	/* Cleanup any existing information if present */
	afc_cleanup_available_spectrum_inquiry_request_list(spec_inq_req_msg);

	/* Read wait timeout for CURL operation */
	spec_inq_req_msg->curl_wait_timeout = afc_nvram_safe_get_int(NULL,
		AFC_NVRAM_CURL_WAIT_TIMEOUT, AFC_DEF_CURL_WAIT_TIMEOUT);

	/* Read base URL from NVRAM if not present use default */
	nvval = afc_nvram_safe_get(AFC_NVRAM_URL);
	if (!strlen(nvval)) {
		AFC_DEBUG("NVRAM %s not defined. Apply Default %s\n", AFC_NVRAM_URL, AFC_BASE_URL);
		nvval = AFC_BASE_URL;
	}
	spec_inq_req_msg->base_url = strdup(nvval);
	if (spec_inq_req_msg->base_url == NULL) {
		AFC_ERROR("Memory allocation for base URL failed. Error[%s]\n", strerror(errno));
		ret = AFCE_MALLOC;
		goto end;
	}

	/* Read TLS cacert path from NVRAM; ignore and proceed if the nvram is not set */
	nvval = afc_nvram_safe_get(AFC_NVRAM_TLS_CACERT);
	if (!strlen(nvval)) {
		AFC_DEBUG("NVRAM %s not defined.\n", AFC_NVRAM_TLS_CACERT);
		if (spec_inq_req_msg->tls_cacert) {
			free(spec_inq_req_msg->tls_cacert);
			spec_inq_req_msg->tls_cacert = NULL;
		}
	} else {
		spec_inq_req_msg->tls_cacert = strdup(nvval);
		if (spec_inq_req_msg->tls_cacert == NULL) {
			AFC_ERROR("Memory allocation for tls_cacert failed. Error[%s]\n",
					strerror(errno));
			ret = AFCE_MALLOC;
			goto end;
		}
		AFC_INFO("NVRAM %s=%s copied to tls_cacert\n", AFC_NVRAM_TLS_CACERT,
				spec_inq_req_msg->tls_cacert);
	}

	/* Read mTLS cert path from NVRAM; ignore and proceed if the nvram is not set */
	nvval = afc_nvram_safe_get(AFC_NVRAM_MTLS_CERT);
	if (!strlen(nvval)) {
		AFC_DEBUG("NVRAM %s not defined.\n", AFC_NVRAM_MTLS_CERT);
		if (spec_inq_req_msg->mtls_cert) {
			free(spec_inq_req_msg->mtls_cert);
			spec_inq_req_msg->mtls_cert = NULL;
		}
	} else {
		spec_inq_req_msg->mtls_cert = strdup(nvval);
		if (spec_inq_req_msg->mtls_cert == NULL) {
			AFC_ERROR("Memory allocation for mtls_cert failed. Error[%s]\n",
					strerror(errno));
			ret = AFCE_MALLOC;
			goto end;
		}
		AFC_INFO("NVRAM %s=%s copied to mtls_cert\n", AFC_NVRAM_MTLS_CERT,
				spec_inq_req_msg->mtls_cert);
	}

	/* Copy the method */
	AFCSTRNCPY(spec_inq_req_msg->method, AFC_METHOD_AVAILABLE_SPECTRUM_INQUIRY,
		sizeof(spec_inq_req_msg->method));

	/* Read AFC version */
	nvval = afc_nvram_safe_get_def(AFC_NVRAM_VERSION,
			AFC_AVAILABLE_SPECTRUM_INQUIRY_METHOD_VERSION);
	snprintf(spec_inq_req_msg->req_version, sizeof(spec_inq_req_msg->req_version), "%s", nvval);

	afc_glist_init(&spec_inq_req_msg->spec_inq_req);

	/* Allocate Available Spectrum Inquiry Request structure */
	spec_inq_req = (avl_spec_inq_req_t*)afc_malloc(sizeof(*spec_inq_req), &ret);
	AFC_ASSERT();

	afc_glist_init(&spec_inq_req->inq_freq_range);
	afc_glist_init(&spec_inq_req->inq_chans);

	afc_get_new_request_id(spec_inq_req_msg, spec_inq_req->request_id,
		sizeof(spec_inq_req->request_id), request_id);

	afc_read_device_description(&spec_inq_req->dev_desc);

	/* Add this newly Allocated Available Spectrum Inquiry Request item to list */
	afc_glist_append(&spec_inq_req_msg->spec_inq_req, (dll_t *)spec_inq_req);

	ret = afc_read_location(spec_inq_req_msg, locpold_fd,
			&spec_inq_req->location, &spec_inq_req->seq_no);
	/* Special handling in case geolocation is read from nvram */
	if (ret == AFCE_NVRAM_GEOLOC) {
		if (spec_inq_req->location.ellipse.center.longitude == AFC_DEF_LONGITUDE &&
			spec_inq_req->location.ellipse.center.latitude == AFC_DEF_LATITUDE) {
			AFC_INFO("GeoLoc Ellipse center is missing : Longitude [%.17g], "
					"Latitude[%.17g]\n",
					spec_inq_req->location.ellipse.center.longitude,
					spec_inq_req->location.ellipse.center.latitude);
			ret = AFCE_INV_ARG;
			afc_glist_delete(&spec_inq_req_msg->spec_inq_req, (dll_t*)spec_inq_req);
			goto end;
		}

		if (spec_inq_req_msg->afc_process_spec_inq_req_item) {
			return spec_inq_req_msg->afc_process_spec_inq_req_item(spec_inq_req);
		}
	}

	if (ret != AFCE_OK) {
		/* Remove from the list */
		afc_glist_delete(&spec_inq_req_msg->spec_inq_req, (dll_t*)spec_inq_req);
		goto end;
	}

end:
	if ((ret != AFCE_OK) && spec_inq_req) {
		afc_cleanup_spectrum_inquiry_request_object(spec_inq_req);
		free(spec_inq_req);
	}

	AFC_EXIT();
	return ret;
}

/* Create and send Available Spectrum Inquiry Request */
int
afc_perform_available_spectrum_inquiry_req(avl_spec_inq_req_msg_t *spec_inq_req_msg,
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	int ret = AFCE_OK;
	char *json_data = NULL;
	afc_curl_output_t curl_output;
	AFC_ENTER();

	AFC_INFO("Initiate Available Spectrum Inquiry Request\n");

	memset(&curl_output, 0, sizeof(curl_output));

	/* Create JSON data from request */
	json_data = (char*)afc_json_data_from_request(spec_inq_req_msg);
	if (!json_data) {
		goto end;
	}
	AFC_DEBUG("JSON Input to AFC System: \n%s\n", json_data);

	afc_write_to_file(REQUEST_JSON_FILENAME, json_data, strlen(json_data)); // Log json request

	/* An Available Spectrum Inquiry Request message is sent by an AFC Device to an AFC System
	 * or retrieval of Available Spectrum information, and an Available Spectrum Inquiry
	 * Response message is sent by an AFC System responding to the Available Spectrum Inquiry
	 * Request message sent by the AFC Device
	 */
	ret = afc_curl_send_request(spec_inq_req_msg, json_data,
		AFC_METHOD_AVAILABLE_SPECTRUM_INQUIRY, &curl_output);
	if (ret == 0) {
		AFC_DEBUG("%zu bytes retrieved from AFC System\n", curl_output.size);
		AFC_DEBUG("JSON output from AFC System : \n%s\n", curl_output.data);

		/* Process the JSON response and store it in structure */
		ret = afc_json_parse_response_data(curl_output.data, curl_output.size,
			spec_inq_resp_msg);
		if (ret == AFCE_OK) {
			afc_write_to_file(RESPONSE_JSON_FILENAME, curl_output.data,
				curl_output.size);
		}
	}

end:
	/* Free the json data created from request */
	if (json_data) {
		free(json_data);
	}

	/* Free the JSON data received from server */
	if (curl_output.data) {
		free(curl_output.data);
	}

	AFC_EXIT();
	return ret;
}

/* Read Available Spectrum Inquiry Response from file and store it in a structure */
int
afc_read_available_spectrum_inquiry_response_from_file(
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	int ret = AFCE_OK;
	char *data = NULL;
	size_t size = 0;
	AFC_ENTER();

	AFC_INFO("Read Available Spectrum Inquiry Response from file(%s) if present\n",
		RESPONSE_JSON_FILENAME);

	if (afc_read_file(RESPONSE_JSON_FILENAME, &data, &size) <= 0) {
		ret = AFCE_FILE_NOT_EXIST;
		goto end;
	}
	AFC_DEBUG("%zu bytes retrieved from file %s\n", size, RESPONSE_JSON_FILENAME);
	AFC_DEBUG("file output : \n%s\n", data);

	ret = afc_json_parse_response_data(data, size, spec_inq_resp_msg);

	if (ret == AFCE_OK) {
		afc_dump_available_spectrum_inquiry_response(spec_inq_resp_msg);
		ret = afc_consume_available_spectrum_inquiry_response(spec_inq_resp_msg);
	}

end:
	if (data) {
		free(data);
	}

	AFC_EXIT();
	return ret;
}

/* Cleanup device description entries */
static void
afc_cleanup_device_descriptor(afc_device_descriptor_t *dev_desc)
{
	AFC_ENTER();

	afc_glist_cleanup(&(dev_desc->certification_Id));

	AFC_EXIT();
}

/* Cleanup location entries */
static void
afc_cleanup_location_object(afc_location_t *location)
{
	AFC_ENTER();

	afc_glist_cleanup(&(location->linear_polygon));

	afc_glist_cleanup(&(location->radial_polygon.outer_boundary));

	AFC_EXIT();
}

/* Cleanup channels entries */
static void
afc_cleanup_channels_object(avl_spec_inq_req_t *spec_inq_req)
{
	afc_inq_chans_t *inq_chans;
	dll_t *inq_chans_item_p;
	AFC_ENTER();

	foreach_glist_item(inq_chans_item_p, spec_inq_req->inq_chans) {

		inq_chans = (afc_inq_chans_t*)inq_chans_item_p;

		if (inq_chans->chan_cfi) {
			free(inq_chans->chan_cfi);
			inq_chans->chan_cfi = NULL;
		}
		inq_chans->chan_cfi_count = 0;
	}

	afc_glist_cleanup(&(spec_inq_req->inq_chans));

	AFC_EXIT();
}

/* Cleanup Available Spectrum Inquiry request object */
static void
afc_cleanup_spectrum_inquiry_request_object(avl_spec_inq_req_t *spec_inq_req)
{
	afc_cleanup_device_descriptor(&(spec_inq_req->dev_desc));

	afc_cleanup_location_object(&(spec_inq_req->location));

	afc_glist_cleanup(&(spec_inq_req->inq_freq_range));

	afc_cleanup_channels_object(spec_inq_req);
}

/* Cleanup Available Spectrum Inquiry request entries */
void
afc_cleanup_available_spectrum_inquiry_request_list(avl_spec_inq_req_msg_t *spec_inq_req_msg)
{
	avl_spec_inq_req_t *spec_inq_req = NULL;
	dll_t *spec_inq_req_item_p;
	AFC_ENTER();

	AFC_INFO("Cleanup Available Spectrum Inquiry Request entries if present\n");

	if (spec_inq_req_msg->spec_inq_req.count <= 0) {
		AFC_INFO("Available Spectrum Inquiry Request entries not present\n");
		goto end;
	}

	foreach_glist_item(spec_inq_req_item_p, spec_inq_req_msg->spec_inq_req) {

		spec_inq_req = (avl_spec_inq_req_t*)spec_inq_req_item_p;

		afc_cleanup_spectrum_inquiry_request_object(spec_inq_req);
	}

	afc_glist_cleanup(&(spec_inq_req_msg->spec_inq_req));

	if (spec_inq_req_msg->base_url) {
		free(spec_inq_req_msg->base_url);
		spec_inq_req_msg->base_url = NULL;
	}

	if (spec_inq_req_msg->tls_cacert) {
		free(spec_inq_req_msg->tls_cacert);
		spec_inq_req_msg->tls_cacert = NULL;
	}

	if (spec_inq_req_msg->mtls_cert) {
		free(spec_inq_req_msg->mtls_cert);
		spec_inq_req_msg->mtls_cert = NULL;
	}

end:
	AFC_EXIT();
}

/* Cleanup available channel info object */
void
afc_cleanup_available_channel_info_object(afc_avl_chan_info_t *avl_chan_info)
{
	if (avl_chan_info->chan_cfi) {
		free(avl_chan_info->chan_cfi);
		avl_chan_info->chan_cfi = NULL;
	}
	avl_chan_info->chan_cfi_count = 0;

	if (avl_chan_info->max_eirp) {
		free(avl_chan_info->max_eirp);
		avl_chan_info->max_eirp = NULL;
	}
	avl_chan_info->max_eirp_count = 0;
}

/* Cleanup channel info response entries */
static void
afc_cleanup_channel_info_response(afc_avl_spec_inq_resp_t *spec_inq_resp)
{
	afc_avl_chan_info_t *avl_chan_info;
	dll_t *avl_chan_info_item_p;
	AFC_ENTER();

	foreach_glist_item(avl_chan_info_item_p, spec_inq_resp->avl_chan_info) {

		avl_chan_info = (afc_avl_chan_info_t*)avl_chan_info_item_p;

		afc_cleanup_available_channel_info_object(avl_chan_info);
	}

	afc_glist_cleanup(&(spec_inq_resp->avl_chan_info));

	AFC_EXIT();
}

/* Cleanup response object entries */
static void
afc_cleanup_response_object(afc_response_t *response)
{
	afc_suppl_info_t *suppl_info;
	AFC_ENTER();

	suppl_info = &response->suppl_info;

	if (suppl_info->mis_params) {
		free(suppl_info->mis_params);
		suppl_info->mis_params = NULL;
	}
	suppl_info->mis_params_count = 0;

	if (suppl_info->inv_params) {
		free(suppl_info->inv_params);
		suppl_info->inv_params = NULL;
	}
	suppl_info->inv_params_count = 0;

	if (suppl_info->unexpected_params) {
		free(suppl_info->unexpected_params);
		suppl_info->unexpected_params = NULL;
	}
	suppl_info->unexpected_params_count = 0;

	AFC_EXIT();
}

/* Cleanup Available Spectrum Inquiry Response object */
void
afc_cleanup_available_spectrum_inquiry_response_object(afc_avl_spec_inq_resp_t *spec_inq_resp)
{
	afc_glist_cleanup(&(spec_inq_resp->avl_freq_info));

	afc_cleanup_channel_info_response(spec_inq_resp);

	afc_cleanup_response_object(&(spec_inq_resp->response));
}

/* Cleanup Available Spectrum Inquiry Response entries */
void
afc_cleanup_available_spectrum_inquiry_response_list(afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	afc_avl_spec_inq_resp_t *spec_inq_resp = NULL;
	dll_t *spec_inq_resp_item_p;
	AFC_ENTER();

	AFC_INFO("Cleanup Available Spectrum Inquiry Response Structure\n");

	spec_inq_resp_msg->flags &= ~AFC_RESP_FLAGS_RESP_EXPIRED;

	/* Do not proceed if empty */
	if (spec_inq_resp_msg->spec_inq_resp.count <= 0) {
		AFC_INFO("Available Spectrum Inquiry Response is not available\n");
		goto end;
	}

	foreach_glist_item(spec_inq_resp_item_p, spec_inq_resp_msg->spec_inq_resp) {

		spec_inq_resp = (afc_avl_spec_inq_resp_t*)spec_inq_resp_item_p;

		afc_cleanup_available_spectrum_inquiry_response_object(spec_inq_resp);
	}

	afc_glist_cleanup(&(spec_inq_resp_msg->spec_inq_resp));

end:
	AFC_EXIT();
}

/* AFC API to get the NVRAM value. */
char*
afc_nvram_safe_get(const char *nvram)
{
	return nvram_safe_get(nvram);
}

/* AFC API to get the NVRAM value, if not found applies default value */
char*
afc_nvram_safe_get_def(const char *nvram, char *def)
{
	char *val = NULL;
	char *ret = def;
	AFC_ENTER();

	val = afc_nvram_safe_get(nvram);

	if (val[0] != '\0') {
		ret = val;
	} else {
		AFC_DEBUG("NVRAM %s is not defined. Apply default %s\n", nvram, ret ? ret : "");
	}

	AFC_EXIT();
	return ret;
}

/* Gets the double val from NVARM, if not found applies the default value */
double
afc_nvram_safe_get_double(char* prefix, const char *nvram, double def)
{
	char *val = NULL;
	double ret = def;
	char final_nvram[NVRAM_MAX_PARAM_LEN];
	AFC_ENTER();

	snprintf(final_nvram, sizeof(final_nvram), "%s%s", prefix ? prefix : "", nvram);
	final_nvram[sizeof(final_nvram) - 1] = '\0';
	val = afc_nvram_safe_get(final_nvram);

	if (val && (val[0] != '\0')) {
		sscanf(val, "%lf", &ret);
	} else {
		AFC_DEBUG("NVRAM %s%s is not defined. Apply Default %.17g\n",
			(prefix ? prefix : ""), nvram, def);
	}

	AFC_EXIT();
	return ret;
}

/* Gets the integer val from NVARM, if not found applies the default value */
int
afc_nvram_safe_get_int(char* prefix, const char *nvram, int def)
{
	char *val = NULL;
	int ret = def;
	char final_nvram[NVRAM_MAX_PARAM_LEN];
	AFC_ENTER();

	snprintf(final_nvram, sizeof(final_nvram), "%s%s", prefix ? prefix : "", nvram);
	final_nvram[sizeof(final_nvram) - 1] = '\0';
	val = afc_nvram_safe_get(final_nvram);

	if (val && (val[0] != '\0')) {
		ret = (int)strtol(val, NULL, 0);
	} else {
		AFC_DEBUG("NVRAM %s%s is not defined. Apply Default %d\n",
			(prefix ? prefix : ""), nvram, def);
	}

	AFC_EXIT();
	return ret;
}

/* Gets the unsigned integer val from NVARM, if not found applies the default value */
uint32
afc_nvram_safe_get_uint(char* prefix, const char *nvram, uint32 def)
{
	char *val = NULL;
	uint32 ret = def;
	char final_nvram[NVRAM_MAX_PARAM_LEN];
	AFC_ENTER();

	snprintf(final_nvram, sizeof(final_nvram), "%s%s", prefix ? prefix : "", nvram);
	final_nvram[sizeof(final_nvram) - 1] = '\0';
	val = afc_nvram_safe_get(final_nvram);

	if (val && (val[0] != '\0')) {
		ret = (uint32)strtoul(val, NULL, 0);
	} else {
		AFC_DEBUG("NVRAM %s%s is not defined. Apply Default %u\n",
			(prefix ? prefix : ""), nvram, def);
	}

	AFC_EXIT();
	return ret;
}

/* Get the tiemout to perform Available Spectrum Inquiry Request */
uint32
afc_get_available_spectrum_inquiry_req_timeout(afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	afc_avl_spec_inq_resp_t *spec_inq_resp = NULL;
	dll_t *spec_inq_resp_item_p;
	uint32 timeout = AFC_MAX_INQ_REQ_TIMEOUT;
	time_t cur_time;
	AFC_ENTER();

	/* Do not proceed if empty */
	if (spec_inq_resp_msg->spec_inq_resp.count <= 0) {
		AFC_INFO("no prior responses found; timeout is 0\n");
		timeout = 0;
		goto end;
	}

	foreach_glist_item(spec_inq_resp_item_p, spec_inq_resp_msg->spec_inq_resp) {

		spec_inq_resp = (afc_avl_spec_inq_resp_t*)spec_inq_resp_item_p;

		cur_time = time(NULL);

		if (spec_inq_resp->avl_exp_tm < cur_time) {
			spec_inq_resp_msg->flags |= AFC_RESP_FLAGS_RESP_EXPIRED;
			AFC_WARNING("spectrum availability specified in this response has expired. "
				"spec_inq_resp->avl_exp_tm[%lu] < cur_time[%lu]\n",
				(unsigned long)(spec_inq_resp->avl_exp_tm),
				(unsigned long)(cur_time));
			timeout = 0;
			break;
		} else {
			uint32 sub_timeout = (uint32)(spec_inq_resp->avl_exp_tm - cur_time);
			AFC_INFO("spectrum availability specified in this response will expire in "
				"another %u seconds\n", sub_timeout);
			if (sub_timeout < timeout) {
				timeout = sub_timeout;
			}
		}
	}

end:
	AFC_EXIT();
	return timeout;
}

/* Dump Available Frequency Info entries */
static void
afc_dump_available_frequency_info(afc_avl_spec_inq_resp_t *spec_inq_resp)
{
	afc_avl_freq_info_t *avl_freq_info;
	dll_t *avl_freq_info_item_p;
	AFC_ENTER();

	AFC_PRINTF("Available Frequency Info\n");

	/* Do not proceed if empty */
	if (spec_inq_resp->avl_freq_info.count <= 0) {
		AFC_INFO("Available Frequency Info is not available\n");
		goto end;
	}

	foreach_glist_item(avl_freq_info_item_p, spec_inq_resp->avl_freq_info) {

		avl_freq_info = (afc_avl_freq_info_t*)avl_freq_info_item_p;

		AFC_PRINTF("===================================================================\n");
		AFC_PRINTF("%-15s%-15s%-25s\n", "Low Frequency", "High Frequency",
			"Max permissible EIRP(dBm)");
		AFC_PRINTF("===================================================================\n");

		AFC_PRINTF("%-15u%-15u  %.17g\n",
				avl_freq_info->freq_range.low_frequency,
				avl_freq_info->freq_range.high_frequency,
				avl_freq_info->max_psd);
		AFC_PRINTF("===================================================================\n");
		AFC_PRINTF("\n");
	}

end:
	AFC_EXIT();
}

/* Dump Available Channel Info entries */
static void
afc_dump_available_channel_info(afc_avl_spec_inq_resp_t *spec_inq_resp)
{
	afc_avl_chan_info_t *avl_chan_info;
	dll_t *avl_chan_info_item_p;
	uint8 i;
	chanspec_t chspec;
	char strchspec[AFC_MAX_BUF_32];
	AFC_ENTER();

	AFC_PRINTF("Available Channel Info\n");

	/* Do not proceed if empty */
	if (spec_inq_resp->avl_chan_info.count <= 0) {
		AFC_INFO("Available Channel Info is not available\n");
		goto end;
	}

	foreach_glist_item(avl_chan_info_item_p, spec_inq_resp->avl_chan_info) {

		avl_chan_info = (afc_avl_chan_info_t*)avl_chan_info_item_p;

		AFC_PRINTF("===================================================================\n");
		AFC_PRINTF("Global Operating Class: %d\n", avl_chan_info->opclass);
		AFC_PRINTF("%-10s%-20s%-25s\n", "Channel", "Chanspec", "Max permissible EIRP(dBm)");
		AFC_PRINTF("===================================================================\n");

		for (i = 0;
			(i < avl_chan_info->chan_cfi_count) && (i < avl_chan_info->max_eirp_count);
			i++) {

			bcmwifi_rclass_get_chanspec_from_chan(BCMWIFI_RCLASS_TYPE_GBL,
				avl_chan_info->opclass, avl_chan_info->chan_cfi[i], &chspec);
			wf_chspec_ntoa(chspec, strchspec);
			AFC_PRINTF("%-10u%-10s(0x%x)  %f\n",
				avl_chan_info->chan_cfi[i], strchspec, chspec,
				avl_chan_info->max_eirp[i]);
		}
		AFC_PRINTF("===================================================================\n");
		AFC_PRINTF("\n");
	}

end:
	AFC_EXIT();
}

/* Convenience macros relevant only to the following functions */
#define I8FLOORF(F) ({int8 I = (int8)(F); if ((F) <= (float)INT8_MIN) {I = INT8_MIN;} \
		else { if ((F) >= (float)INT8_MAX) {I = INT8_MAX;} \
		else {if ((F) < 0 && ((float)I) != (F)) {I = (int) ((F) - 1);}}} I;})
#define AFC_CALC_QDB_OFF(max_db) ((max_db) * 4 + 1 - 127)   /* qdB offset to fit max_db in int8 */
#define AFC_DB_TO_QDB(db, qoff)	I8FLOORF((db) * 4 - (qoff)) /* Convert dB to qDb applying offset */
#define AFC_DEFAULT_EXPIRY_SECS	(24 * 60 * 60)		/* expires in 24 hours by default */
#define AFC_IS_6G_CENTER_20MHZ(cc) ((cc) == 2 || ((cc) % 4) == 1)
#define AFC_20MHZ_EIRP_TO_PSD_DB(eirp) ((eirp) - 13)	/* 10 * Log(20) ~= 13 */

/* SP center channels - FCC */
static uint8 afc_fcc_sp_cc_list[] = {
	/* UNII-5 20MHz : 6g2 */
	2,
	/* UNII-5 20MHz : 6g1 - 6g93 */
	1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93,
	/* UNII-7 20MHz : 6g117 - 6g181 */
	117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181,
	/* UNII-5 & 7 40MHz */
	3, 11, 19, 27, 35, 43, 51, 59, 67, 75, 83, 91, 123, 131, 139, 147, 155, 163, 171, 179,
	/* UNII-5 & 7 80MHz */
	7, 23, 39, 55, 71, 87, 135, 151, 167,
	/* UNII-5 & 7 160MHz */
	15, 47, 79, 143,
	/* UNII-5 320MHz */
	31, 63
};

static size_t afc_fcc_sp_cc_list_len = ARRAYSIZE(afc_fcc_sp_cc_list);

/* SP center channels - CA (Canada) */
static uint8 afc_ca_sp_cc_list[] = {
	/* UNII-5 20MHz : 6g2 */
	2,
	/* UNII-5 20MHz : 6g1 - 6g93 */
	1, 5, 9, 13, 17, 21, 25, 29, 33, 37, 41, 45, 49, 53, 57, 61, 65, 69, 73, 77, 81, 85, 89, 93,
	/* UNII-6 20MHz : 6g97 - 6g113 */
	97, 101, 105, 109, 113,
	/* UNII-7 20MHz : 6g117 - 6g181 */
	117, 121, 125, 129, 133, 137, 141, 145, 149, 153, 157, 161, 165, 169, 173, 177, 181,
	/* UNII-5 40MHz */
	3, 11, 19, 27, 35, 43, 51, 59, 67, 75, 83, 91,
	/* UNII-6 40MHz */
	99, 107, 115,
	/* UNII-7 40MHz */
	123, 131, 139, 147, 155, 163, 171, 179,
	/* UNII-5, 6 & 7 80MHz */
	7, 23, 39, 55, 71, 87, 103, 119, 135, 151, 167,
	/* UNII-5, 6 & 7 160MHz */
	15, 47, 79, 111, 143,
	/* UNII-5, 6 & 7 320MHz */
	31, 63, 95, 127
};

static size_t afc_ca_sp_cc_list_len = ARRAYSIZE(afc_ca_sp_cc_list);

/*
 * The function returns the index to the 'needle' in unsorted 'haystack' array of length
 * 'haystack_len' or -1 on failure to find.
 */
static int32 afc_find_in_arr_uint8(uint8 needle, uint8 *haystack, uint16 haystack_len)
{
	uint16 i;

	for (i = 0; i < haystack_len; ++i) {
		if (haystack[i] == needle) {
			return (int32) i;
		}
	}

	return -1;
}

/* MACROs relevant to the following function only */
#define AFC_PSD_DB_INVALID (-128.0)
#define AFC_IS_PSD_DB_VALID(X) ((X) > AFC_PSD_DB_INVALID)

/* returns 6GHz channel index given a 6GHz frequency in MHz.
 *     1 for freq in channel 6g1 (5945-5964), 2 for 6g5 (5965-5984), 3 for 6g9 ...
 * exception: returns 0 for 6g2 (5925-2544)
 */
#define AFC_FREQ_TO_IDX(FREQ) (((int)(FREQ) - 5925)/20)

/* returns 6GHz 20MHz channel number to index
 *     1 for channel 6g1, 2 for 6g5, 3 for 6g9, ...
 * exception: returns 0 for 6g2
 */
#define AFC_CH_TO_IDX(CC) ((CC) == 2 ? 0 : ((CC)/4 + 1))

#define MAX_20MHZ_CHANNELS ((MAXCHANNEL_NUM) >> 2)
/* Translate AFC response containing available channel/frequency info to the driver */
static void
afc_resp_to_driver(afc_avl_spec_inq_resp_t *spec_inq_resp, uint32 timeout)
{
	int ret = AFCE_OK;
	afc_avl_freq_info_t *avl_freq_info;
	dll_t *avl_freq_info_item_p;
	afc_avl_chan_info_t *avl_chan_info;
	dll_t *avl_chan_info_item_p;
	uint16 i, if_index, num_cc_20 = 0;
	/* IOV related */
	wl_afc_info_t *wl_ai = NULL;
	size_t wl_ai_sz;
	int max_db = 0;
	uint8 ch_buf[WLC_IOCTL_MAXLEN] = {0}, buf[WL_AFC_INFO_MAX_SZ] = {0};
	wl_uint32_list_t *ch_list;
	double max_psd[MAX_20MHZ_CHANNELS]; // maxPSD per 20MHz channel index : lowest in the range
	uint8 *sp_cc_list = afc_fcc_sp_cc_list;
	size_t sp_cc_list_len = afc_fcc_sp_cc_list_len;

	AFC_ENTER();

	/* Do not proceed if both freq and chan info are empty */
	if (spec_inq_resp->avl_freq_info.count <= 0 && spec_inq_resp->avl_chan_info.count <= 0) {
		AFC_INFO("Available Freq (%d) and Channel Info (%d) are empty?\n",
				spec_inq_resp->avl_freq_info.count,
				spec_inq_resp->avl_chan_info.count);
		// goto end;
	}

	if (!g_afc_num_ifnames || g_afc_ifnames[0][0] == '\0') {
		AFC_INFO("ifnames list is empty %d\n", g_afc_num_ifnames);
		goto end;
	}

	for (if_index = 0; if_index < g_afc_num_ifnames; ++if_index) {
		num_cc_20 = 0;
		chanspec_t input = 0;
		memset(ch_buf, 0, WLC_IOCTL_MAXLEN);
		memset(buf, 0, WL_AFC_INFO_MAX_SZ);
		/* chanspec_t input = WL_CHANSPEC_BAND_6G | WL_CHANSPEC_BW_320 |
		 * WL_CHANSPEC_BW_160 | WL_CHANSPEC_BW_80 | WL_CHANSPEC_BW_40 | WL_CHANSPEC_BW_20;
		 */

		if (wl_iovar_getbuf(g_afc_ifnames[if_index], "chanspecs", &input, sizeof(input),
				ch_buf, sizeof(ch_buf)) != 0) {
			AFC_INFO("%s_chanspecs get fail\n", g_afc_ifnames[if_index]);
			continue;
		}

		if (g_afc_ifnames[if_index][0] && afc_is_cc_canada(g_afc_ifnames[if_index])) {
			AFC_PRINT("Info: ", "Switching to Canada channel list\n");
			sp_cc_list = afc_ca_sp_cc_list;
			sp_cc_list_len = afc_ca_sp_cc_list_len;
		}

		ch_list = (wl_uint32_list_t *)ch_buf;
		ch_list->count = dtoh32(ch_list->count);
		if (!ch_list->count) {
			AFC_ERROR("chanspecs list count (%d) from the driver is invalid\n", ch_list->count);
			goto end;
		}
		AFC_INFO("Got chanspecs list count (%d) from the driver\n", ch_list->count);

		wl_ai_sz = WL_AFC_INFO_MAX_SZ;
		wl_ai = (wl_afc_info_t*)afc_malloc(wl_ai_sz, &ret);
		AFC_DEBUG("Allocated afc_info wl_ai:%p, wl_ai_sz:%zu, ret:%d\n", wl_ai, wl_ai_sz, ret);
		AFC_ASSERT();

		if (!wl_ai) {
			AFC_ERROR("Alloc afc_info failed wl_ai:%p/NULL, wl_ai_sz:%zu\n", wl_ai, wl_ai_sz);
			goto end;
		}

		wl_ai->ver = WL_AFC_INFO_VER;
		wl_ai->len = wl_ai_sz;
		memset(wl_ai->qdb, WL_AFC_INVALID_QDB, wl_ai_sz - WL_AFC_INFO_MIN_SZ); // fill with -128qdB

		/* Ensure 20MHz channels are filled in wl_ai->center_ch[] first */
		for (i = 0; (i < ch_list->count) && (wl_ai->num_ch < ARRAYSIZE(wl_ai->center_ch)); ++i) {
			chanspec_t chsp = (chanspec_t) dtoh32(ch_list->element[i]);
			uint8 center_ch = CHSPEC_CHANNEL(chsp);
			AFC_DEBUG("center_ch:%u, chsp:0x%04X.\n", center_ch, chsp);
			if (!CHSPEC_IS20(chsp) || !CHSPEC_IS6G(chsp)) { /* is NOT 20MHz or not 6GHz */
				AFC_TRACE("---- Skipping non-20MHz/non-6GHz chsp:0x%04X.\n", chsp);
				continue;
			}
			if (afc_find_in_arr_uint8(center_ch, wl_ai->center_ch, num_cc_20) >= 0) {
				/* already present in center_ch array */
				AFC_TRACE("---- Skipping already added center_ch:%u\n", center_ch);
				continue;
			}
			/* must be valid as per SP channels list */
			if (afc_find_in_arr_uint8(center_ch, sp_cc_list, sp_cc_list_len) >= 0) {
				AFC_DEBUG("---- Adding center_ch:%u @%u\n",
						center_ch, num_cc_20);
				wl_ai->center_ch[num_cc_20++] = center_ch;
			}
		}
		wl_ai->num_ch = (uint8)(num_cc_20 & 0xFFu);
		AFC_INFO("num_ch so far = num_cc_20:%u\n", num_cc_20);

		/* Fill non-20MHz channels (now that 20MHz channels are already placed atop) */
		for (i = 0; (i < ch_list->count) && (wl_ai->num_ch < ARRAYSIZE(wl_ai->center_ch)); ++i) {
			chanspec_t chsp = (chanspec_t) dtoh32(ch_list->element[i]);
			uint8 center_ch = CHSPEC_CHANNEL(chsp);
			AFC_DEBUG("center_ch:%u, chsp:0x%04X.\n", center_ch, chsp);
			if (CHSPEC_IS20(chsp) || !CHSPEC_IS6G(chsp)) { /* is 20MHz or not 6GHz */
				AFC_TRACE("---- Skipping 20MHz/non-6GHz chsp:0x%04X.\n", chsp);
				continue;
			}
			if (afc_find_in_arr_uint8(center_ch, wl_ai->center_ch, wl_ai->num_ch) >= 0) {
				/* already present in center_ch array */
				AFC_TRACE("---- Skipping already added center_ch:%u\n", center_ch);
				continue;
			}
			/* must be valid as per SP channels list */
			if (afc_find_in_arr_uint8(center_ch, sp_cc_list, sp_cc_list_len) >= 0) {
				AFC_DEBUG("---- Adding center_ch:%u @%u\n",
						center_ch, wl_ai->num_ch);
				wl_ai->center_ch[wl_ai->num_ch++] = center_ch;
			}
		}

		/* for all channels, include EIRP inquired by channel */
		wl_ai->num_qdb_ic_eirp = wl_ai->num_ch;
		/* for all 20MHz channels, include PSD inquired by frequency */
		wl_ai->num_qdb_if_psd  = num_cc_20;
		wl_ai->num_qdb_total   = wl_ai->num_qdb_ic_eirp + wl_ai->num_qdb_if_psd;
		wl_ai_sz = wl_ai->len = WL_AFC_INFO_MIN_SZ + wl_ai->num_qdb_total;

		AFC_INFO("num_ch: %d, num_cc_20=%d, num_qdb_ic_eirp: %d, num_qdb_if_psd: %d, "
				"num_qdb_total: %d, len: %d\n",
				wl_ai->num_ch, num_cc_20, wl_ai->num_qdb_ic_eirp, wl_ai->num_qdb_if_psd,
				wl_ai->num_qdb_total, wl_ai->len);

		/* first pass on 'response to inquiry by channel' to get max_db (to compute qdB offset) */
		foreach_glist_item(avl_chan_info_item_p, spec_inq_resp->avl_chan_info) {
			avl_chan_info = (afc_avl_chan_info_t*)avl_chan_info_item_p;
			for (i = 0;
				(i < avl_chan_info->chan_cfi_count) && (i < avl_chan_info->max_eirp_count);
				++i) {
				if (avl_chan_info->max_eirp[i] > max_db) {
					max_db = (int) (0.5 + avl_chan_info->max_eirp[i]);
				}
			}
		}

		for (i = 0; i < ARRAYSIZE(max_psd); ++i) {
			max_psd[i] = AFC_PSD_DB_INVALID;
		}

		/* first pass on 'response to inquiry by frequency'
		 *  - to get max_db (to compute qdB offset)
		 *  - to store per channel maxPSD
		 */
		foreach_glist_item(avl_freq_info_item_p, spec_inq_resp->avl_freq_info) {
			uint32 resp_lo_mhz, resp_hi_mhz, freq;
			avl_freq_info = (afc_avl_freq_info_t*)avl_freq_info_item_p;
			if (avl_freq_info->max_psd > max_db) {
				max_db = (int) (0.5 + avl_freq_info->max_psd);
			}
			resp_lo_mhz = avl_freq_info->freq_range.low_frequency;	/* resp starting freq */
			resp_hi_mhz = avl_freq_info->freq_range.high_frequency;	/* resp ending freq */
			for (freq = resp_lo_mhz; freq < resp_hi_mhz; freq++) {
				int idx = AFC_FREQ_TO_IDX(freq);

				AFC_DEBUG("max_psd freq:%uMHz idx:%-4u, psd:%lf\n", freq, idx,
						avl_freq_info->max_psd);
				if (idx < 0 || idx >= ARRAYSIZE(max_psd)) {
					AFC_INFO("Skipping max_psd freq:%uMHz idx:%-4d\n",
							freq, idx);
					continue;
				}
				if (!AFC_IS_PSD_DB_VALID(max_psd[idx]) ||
						max_psd[idx] > avl_freq_info->max_psd) {
					/* lowest max_psd for this channel's index is stored */
					max_psd[idx] = avl_freq_info->max_psd;
				}
			}
		}

		wl_ai->reg_info_type = 4;			/* TODO: Fetch from the driver instead */

		wl_ai->expiry = (int32) ((timeout > AFC_MAX_INQ_REQ_TIMEOUT) ?
				AFC_MAX_INQ_REQ_TIMEOUT: timeout);

		wl_ai->qdb_offset = AFC_CALC_QDB_OFF(max_db);

		/* second pass on 'response to inquiry by channel' to copy EIRP values into qdb array */
		foreach_glist_item(avl_chan_info_item_p, spec_inq_resp->avl_chan_info) {
			avl_chan_info = (afc_avl_chan_info_t*)avl_chan_info_item_p;
			for (i = 0;
				(i < avl_chan_info->chan_cfi_count) && (i < avl_chan_info->max_eirp_count);
				++i) {
				int32 cc_idx = afc_find_in_arr_uint8(avl_chan_info->chan_cfi[i],
						wl_ai->center_ch,
						wl_ai->num_ch);
				if (cc_idx < 0 || cc_idx >= wl_ai->num_ch) {
					continue;
				}
				AFC_DEBUG("chan_cfi[%d] = %u, center_ch[%d] = %u, EIRP=%.4lf\n",
						i, avl_chan_info->chan_cfi[i],
						cc_idx, wl_ai->center_ch[cc_idx],
						avl_chan_info->max_eirp[i]);
				wl_ai->qdb[cc_idx] = AFC_DB_TO_QDB(avl_chan_info->max_eirp[i],
						wl_ai->qdb_offset);

				/* fill PSD computed from EIRP till found in inquiry by frequency */
				if (AFC_IS_6G_CENTER_20MHZ(wl_ai->center_ch[cc_idx])) {
					wl_ai->qdb[wl_ai->num_qdb_ic_eirp + cc_idx] = AFC_DB_TO_QDB(
						AFC_20MHZ_EIRP_TO_PSD_DB(avl_chan_info->max_eirp[i]),
						wl_ai->qdb_offset);
				}
			}
		}

		/* copy PSD values into qdb array for 20MHz channels */
		for (i = 0; i < num_cc_20 && i < wl_ai->num_ch; ++i) {
			uint8 cc = wl_ai->center_ch[i];
			int idx = AFC_CH_TO_IDX(cc);

			if (!AFC_IS_6G_CENTER_20MHZ(cc)) {
				AFC_ERROR("Expected 20MHz center channel but got %u at %u\n", cc, i);
				break;
			}

			if (cc < 1 || idx < 0 || idx >= ARRAYSIZE(max_psd)) {
				continue;
			}
			wl_ai->qdb[wl_ai->num_qdb_ic_eirp + i] = AFC_DB_TO_QDB(max_psd[idx],
					wl_ai->qdb_offset);
			AFC_DEBUG("q[%d]:%dqdB (%5.2lfdB), o:%d\n", wl_ai->num_qdb_ic_eirp + i,
					wl_ai->qdb[wl_ai->num_qdb_ic_eirp + i], max_psd[idx],
					wl_ai->qdb_offset);
		}

		/* host to dongle conversions */
		wl_ai->ver = htod16(wl_ai->ver);
		wl_ai->len = htod16(wl_ai->len);
		wl_ai->flags = htod16(wl_ai->flags);
		wl_ai->expiry = htod32(wl_ai->expiry);
		wl_ai->num_qdb_total   = htod16(wl_ai->num_qdb_total);
		wl_ai->num_qdb_ic_eirp = htod16(wl_ai->num_qdb_ic_eirp);
		wl_ai->num_qdb_if_psd  = htod16(wl_ai->num_qdb_if_psd);

		char acs_cmd[256];
		AFC_INFO("setting afc_info for interface %s\n", g_afc_ifnames[if_index]);
		ret = wl_iovar_setbuf(g_afc_ifnames[if_index], "afc_info", wl_ai, wl_ai_sz,
				buf, sizeof(buf));
		AFC_INFO("setting afc_info for interface %s ret:%d %s\n", g_afc_ifnames[if_index], ret,
				(ret ? "Failed" : "Succeeded"));
		/* inform ACSD */
		snprintf(acs_cmd, sizeof(acs_cmd), "acs_cli2 -i %s acs_restart\n",
				g_afc_ifnames[if_index]);
		acs_cmd[sizeof(acs_cmd) -1] = '\0';
		AFC_INFO("Issuing %s\n", acs_cmd);
		system(acs_cmd);

		/* even on failure, continue to the next interface (if any) */
	}

end:
	/* free temporary allocations */
	if (wl_ai) {
		free(wl_ai);
	}
	AFC_EXIT();
}

/* macro specific to the following function */
#define AFC_MAX_TXPWR (33)
#ifndef DIV_QUO
#define DIV_QUO(num, div) ((num)/(div))  /* Return the quotient of division to avoid floats */
#endif
#ifndef DIV_REM
#define DIV_REM(num, div) ((((num)%(div)) * 100)/(div)) /* Return the remainder of division */
#endif

int afc_check_txpwr_max()
{
	char *cmd_name = "chanspec_txpwr_max";
	wl_chanspec_txpwr_max_t params = {0}, *txpwrbuf = NULL;
	uint8 buf[2048] = {0}; /* TODO: Fix driver to accept smaller buffer on qeurying a subset */
	uint16 exp_len = 0;
	int i, ret, sp_qdbm_thresh, sp_count = 0, sp_count_thresh;
	char chspec_str[CHANSPEC_STR_LEN];

	AFC_ENTER();

	sp_qdbm_thresh = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_SP_QDBM_THRESH,
			AFC_DEF_SP_QDBM_THRESH);
	sp_count_thresh = afc_nvram_safe_get_uint(NULL, AFC_NVRAM_SP_COUNT_THRESH,
			AFC_DEF_SP_COUNT_THRESH);

	params.ver = htod16(WL_CHANSPEC_TXPWR_MAX_VER);
	params.len = htod16(WL_CHANSPEC_TXPWR_MAX_LEN);
	params.count = htod32(1);
	params.txpwr[0].chanspec = htod16(WL_CHANSPEC_BAND_6G | WL_CHANSPEC_BW_160); /* subset */

	if ((ret = wl_iovar_getbuf(g_afc_ifnames[0], cmd_name,
			&params, sizeof(params), buf, sizeof(buf))) != BCME_OK) {
		AFC_ERROR("wl -i %s %s -b 6 -w 160 failed (%d)\n", g_afc_ifnames[0], cmd_name, ret);

		goto check_done;
	}

	txpwrbuf = (wl_chanspec_txpwr_max_t *) buf;
	txpwrbuf->ver = dtoh16(txpwrbuf->ver);
	txpwrbuf->len = dtoh16(txpwrbuf->len);
	txpwrbuf->count = dtoh16(txpwrbuf->count);

	if (txpwrbuf->ver != WL_CHANSPEC_TXPWR_MAX_VER) {
		AFC_ERROR("%s failed version check received %u != %u expected\n",
				cmd_name, txpwrbuf->ver, WL_CHANSPEC_TXPWR_MAX_VER);
		goto check_done;
	}
	if (txpwrbuf->count < 1) {
		AFC_ERROR("%s failed count check received %u < 1 expected\n",
				cmd_name, txpwrbuf->count);
		goto check_done;
	}

	exp_len = sizeof(*txpwrbuf) + ((txpwrbuf->count - 1) * sizeof(chanspec_txpwr_max_t));
	if (txpwrbuf->len < exp_len) {
		AFC_INFO("%s failed len check received %u < %u expected for count %u (ignored)\n",
				cmd_name, txpwrbuf->len, exp_len, txpwrbuf->count);
		// TODO: Fix driver to return length matching the count
		// AFC_ERROR();
		// goto check_done;
	}

	for (i = 0; i < txpwrbuf->count; i++) {
		chanspec_txpwr_max_t *txpwr = &txpwrbuf->txpwr[i];
		txpwr->chanspec = dtoh16(txpwr->chanspec);
		txpwr->txpwr_max = MIN(txpwr->txpwr_max, AFC_MAX_TXPWR * 4);
		if (txpwr->txpwr_max >= sp_qdbm_thresh) {
			sp_count++;
		}
		AFC_DEBUG("txpwr of ch %16s / 0x%04X : %2d.%02d dBm  sp_count: %d\n",
				wf_chspec_ntoa(txpwr->chanspec, chspec_str),
				txpwr->chanspec,
				DIV_QUO(txpwr->txpwr_max, 4),
				DIV_REM(txpwr->txpwr_max, 4),
				sp_count);
	}

check_done:
	AFC_INFO("sp_count: %d, sp_count_thresh: %d\n", sp_count, sp_count_thresh);

	AFC_EXIT();

	return ((sp_count > sp_count_thresh) ? AFCE_OK : AFCE_FAIL);
}

/* Loop through Available Spectrum Inquiry Response entries and send to the driver */
int
afc_consume_available_spectrum_inquiry_response(afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	afc_avl_spec_inq_resp_t *spec_inq_resp = NULL;
	dll_t *spec_inq_resp_item_p;
	uint32 timeout = 0;
	int ret = AFCE_OK;

	AFC_ENTER();

	/* Do not proceed if empty */
	if (spec_inq_resp_msg->spec_inq_resp.count <= 0) {
		AFC_INFO("Available Spectrum Inquiry Response Count (%d) is invalid\n",
				spec_inq_resp_msg->spec_inq_resp.count);
		ret = AFCE_FAIL;
		goto end;
	}

	AFC_INFO("Available Spectrum Inquiry Response Count is %d\n",
			spec_inq_resp_msg->spec_inq_resp.count);
	/* TODO: Can the Response Count be > 1. How to consume */

	timeout = afc_get_available_spectrum_inquiry_req_timeout(spec_inq_resp_msg);
	foreach_glist_item(spec_inq_resp_item_p, spec_inq_resp_msg->spec_inq_resp) {
		spec_inq_resp = (afc_avl_spec_inq_resp_t*)spec_inq_resp_item_p;

		afc_resp_to_driver(spec_inq_resp, timeout);
	}

end:
	AFC_EXIT();
	return ret;
}

/* Dump Available Spectrum Inquiry Response entries */
void
afc_dump_available_spectrum_inquiry_response(afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	afc_avl_spec_inq_resp_t *spec_inq_resp = NULL;
	dll_t *spec_inq_resp_item_p;
	AFC_ENTER();

	if (!AFC_IS_INFO()) {
		goto end;
	}

	AFC_INFO("Dump Available Spectrum Inquiry Response\n");

	/* Do not proceed if empty */
	if (spec_inq_resp_msg->spec_inq_resp.count <= 0) {
		AFC_INFO("Available Spectrum Inquiry Response is not available\n");
		goto end;
	}

	AFC_INFO("Available Spectrum Inquiry Response Count is %d\n",
			spec_inq_resp_msg->spec_inq_resp.count);

	foreach_glist_item(spec_inq_resp_item_p, spec_inq_resp_msg->spec_inq_resp) {

		spec_inq_resp = (afc_avl_spec_inq_resp_t*)spec_inq_resp_item_p;

		if (g_afc_msglevel & AFC_DEBUG_INFO) {
			afc_dump_available_frequency_info(spec_inq_resp);

			afc_dump_available_channel_info(spec_inq_resp);
		}
	}

end:
	AFC_EXIT();
}
