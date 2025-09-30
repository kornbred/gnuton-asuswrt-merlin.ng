/*
 * AFC Library Header
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
 * $Id: afc.h 832722 2023-11-12 00:09:11Z $
 */

#ifndef _AFC_H_
#define _AFC_H_

#include <typedefs.h>
#include <bcmutils.h>
#include <bcmendian.h>
#include <ethernet.h>

#define AFC_MAX_URL		2083	/* Max URL Length */
#define AFC_MAX_SERIAL_NUM	32	/* Maximum length of Serial number of a Device */
#define AFC_MAX_CERT_ID		32	/* Max length of Certification ID of an AP */
#define AFC_MAX_HT_TYPE_ID	16	/* Max length of height_type ID of an AP */
#define AFC_MAX_RULESET_ID	128	/* Max length of identifiers of the regulatory rules
					 * supported by an AP
					 */
#define AFC_MAX_TM		25	/* Max length of time FORMAT: YYYY-MM-DDThh:mm:ssZ */
#define AFC_MAX_RESP_DESCR	50	/* Max length of short description of response */
#define AFC_MAX_FIELD_NAME	64	/* Max length of field name */
#define AFC_MAX_VERSION		16	/* Max length of version string */
#define AFC_MAX_STR_REQ_ID	32	/* Max length of request ID string */
#define AFC_MAX_METHOD		64	/* Max length of AFC method */
#define AFC_MAX_BUF_32		32

#ifndef IFNAMSIZ
#define IFNAMSIZ		16
#endif /* IFNAMSIZ */
#define AFCD_MAX_IFACE		4	/* can handle up to these many 6GHz interfaces */

extern bool afc_swap;	/* find dongle endianness and store if h2d / d2h macros need to swap */

int afc_init_swap(char *ifname);

#define htod32(i) (afc_swap?bcmswap32(i):(uint32)(i))
#define htod16(i) (afc_swap?bcmswap16(i):(uint16)(i))
#define dtoh64(i) (afc_swap?bcmswap64(i):(uint64)(i))
#define dtoh32(i) (afc_swap?bcmswap32(i):(uint32)(i))
#define dtoh16(i) (afc_swap?bcmswap16(i):(uint16)(i))
#define htodchanspec(i) (afc_swap?htod16(i):i)
#define dtohchanspec(i) (afc_swap?dtoh16(i):i)
#define htodenum(i) (afc_swap?((sizeof(i) == 4) ? \
			htod32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)
#define dtohenum(i) (afc_swap?((sizeof(i) == 4) ? \
			dtoh32(i) : ((sizeof(i) == 2) ? htod16(i) : i)):i)

extern uint8 g_afc_num_ifnames;				/* Number of entries in ifnames array */
extern char g_afc_ifnames[AFCD_MAX_IFACE][IFNAMSIZ];		/* List of 6GHz interfaces */

/* The version number of the AvailableSpectrumInquiryRequest */
#define AFC_AVAILABLE_SPECTRUM_INQUIRY_METHOD_VERSION	"1.4"

/* AFC inqury type bitmap */
#define AFC_INQ_TYPE_NONE	0u
#define AFC_INQ_TYPE_CHAN	0x01u	/* Inquire by channel */
#define AFC_INQ_TYPE_FREQ	0x02u	/* Inquire by frequency */
#define AFC_INQ_TYPE_ALL	0xFFu

/* AFC modes to dis/allow reading raw geo location nvrams */
#define AFC_READ_RAW_LOC_NEVER		0	/* Do not use geo location nvram values */
#define AFC_READ_RAW_LOC_ALWAYS		1	/* Read geo location from nvram; skip locpold */
#define AFC_READ_RAW_ON_LOCPOL_ERR	2	/* Read geo location nvrams if locpold fails */
#define AFC_READ_RAW_ON_INVALID_LOC	3	/* Read geo location nvrams on invalid values */

/* Default NVRAM values */
#define AFC_DEF_REQ_ID		-1
#define AFC_DEF_ROBUST		0		/* default not robust : not enforcing OCSP etc */
#define AFC_DEF_INSECURE	0		/* default secure : authenticate the web-server */
#define AFC_DEF_INQ_TYPE	AFC_INQ_TYPE_ALL
#define AFC_DEF_CURL_WAIT_TIMEOUT	60	/* wait timeout for CURL operation */
#define AFC_DEF_READ_RAW_LOC	AFC_READ_RAW_LOC_NEVER
#define AFC_DEF_LONGITUDE	0.0
#define AFC_DEF_LATITUDE	0.0
#define AFC_DEF_MAJOR_AXIS	100
#define AFC_DEF_MINOR_AXIS	50
#define AFC_DEF_ORIENTATION	45
#define AFC_DEF_LOC_HEIGHT	3
#define AFC_DEF_LOC_HEIGHT_TYPE	"AGL"
#define AFC_DEF_LOC_VER_UNCERT	2
#define AFC_DEF_LOC_DEPLOYMENT	AFC_INDOOR_DEPLOYMENT_OUTDOOR
#define AFC_DEF_MIN_REQ_GAP	(3u  * 60u)	/* Minimum gap between two web requests in secs */
#define AFC_DEF_MAX_REQ_GAP	(12u * 60u)	/* Maximum gap between two web requests in secs */
#define AFC_DEF_PROXY_LAG	15u		/* Delay initial proxy request by these many secs */

#define AFC_BASE_URL		"https://afc.broadcom.com/fbrat/ap-afc/1.4"
#define AFC_DEF_DEV_SERIAL_NO	"REG123"
#define AFC_DEF_CERT_ID		"FCCID-REG123"
#define AFC_DEF_REG_RULES	"US_47_CFR_PART_15_SUBPART_E"
#define AFC_DEF_VECTOR_LEN	100
#define AFC_DEF_VECTOR_ANGLE	120
#define AFC_DEF_LOC_REQ_TIMEOUT		(5u * 60u)	/* default timeout in seconds for location
							 * requests to locpold.
							 */
#define AFC_DEF_LOC_REQ_MIN_TIMEOUT	(2u * 60u)	/* default minimum timeout in seconds for
							 * location requests to locpold.
							 */

#define AFC_DEF_SP_QDBM_THRESH	((22 * 4) -1)		/* Power threshold. eg. 21.75dBm in qdBm */
#define AFC_DEF_SP_COUNT_THRESH	(16)			/* Atleast these many 160MHz SP chanspecs */

/* NVRAMs */
#define AFC_NVRAM_MSGLEVEL		"afc_msglevel"
#define AFC_NVRAM_ROBUST		"afc_robust"
#define AFC_NVRAM_INSECURE		"afc_insecure"
#define AFC_NVRAM_VERSION		"afc_version"
#define AFC_NVRAM_REQ_ID		"afc_req_id"
#define AFC_NVRAM_INQ_TYPE		"afc_inq_type"
#define AFC_NVRAM_READ_RAW_LOC		"afc_read_raw_loc"
#define AFC_NVRAM_GEO_LONGITUDE		"geo_longitude"
#define AFC_NVRAM_GEO_LATITUDE		"geo_latitude"
#define AFC_NVRAM_MAJOR_AXIS		"afc_major_axis"
#define AFC_NVRAM_MINOR_AXIS		"afc_minor_axis"
#define AFC_NVRAM_ORIENTATION		"afc_orientation"
#define AFC_NVRAM_LOC_HEIGHT		"afc_loc_height"
#define AFC_NVRAM_LOC_HEIGHT_TYPE	"afc_loc_height_type"
#define AFC_NVRAM_LOC_VER_UNCERT	"afc_loc_vert_uncert"
#define AFC_NVRAM_LOC_DEPLOYMENT	"afc_loc_deployment"
#define AFC_NVRAM_CURL_WAIT_TIMEOUT	"afc_curl_wait_tm"
#define AFC_NVRAM_URL			"afc_url"
#define AFC_NVRAM_DEV_SERIAL_NO		"afc_dev_serial_no"
#define AFC_NVRAM_CERT_ID		"afc_cert_id"
#define AFC_NVRAM_REG_RULES		"afc_reg_rules"
#define AFC_NVRAM_VECTOR_LEN		"afc_vector_len"
#define AFC_NVRAM_VECTOR_ANGLE		"afc_vector_angle"
#define AFC_NVRAM_FREQ_RANGE		"afc_freq_range"
#define AFC_NVRAM_OP_CLASS		"afc_op_class"
#define AFC_NVRAM_MIN_REQ_GAP		"afc_min_req_gap"
#define AFC_NVRAM_MAX_REQ_GAP		"afc_max_req_gap"
#define AFC_NVRAM_1905_AL_MAC		"multiap_almac"
#define AFC_NVRAM_TLS_CACERT		"afc_tls_cacert"
#define AFC_NVRAM_MTLS_CERT		"afc_mtls_cert"
#define AFC_NVRAM_PROXY_LAG		"afc_proxy_lag"
#define AFC_NVRAM_LOC_REQ_TIMEOUT	"afc_loc_req_timeout"
#define AFC_NVRAM_SP_QDBM_THRESH	"afc_sp_qdbm_thresh"
#define AFC_NVRAM_SP_COUNT_THRESH	"afc_sp_count_thresh"

#define AFCSTRNCPY(dst, src, len)	 \
	do { \
		strncpy((dst), (src), (len)); \
		(dst)[len - 1] = '\0'; \
	} while (0)

/* Define a Generic List */
typedef struct afc_glist {
	uint count;	/* Count of list of objects */
	dll_t head;	/* Head Node of list of objects */
} afc_glist_t;

/* Traverse each item of a Generic List */
#define foreach_glist_item(item, list) \
		for ((item) = dll_head_p(&((list).head)); \
			! dll_end(&((list).head), (item)); \
			(item) = dll_next_p((item)))

/* Traverse each item of a Generic List, Check for additional condition */
#define foreach_glist_item_ex(item, list, condition) \
		for ((item) = dll_head_p(&((list).head)); \
			((!dll_end(&((list).head), item))&& ((condition))); \
			(item) = dll_next_p((item)))

/* Traverse each item of a Generic List, with keep track of next node */
#define foreach_safe_glist_item(item, list, next) \
		for ((item) = dll_head_p(&((list).head)); \
			!dll_end(&((list).head), (item)); \
			(item) = (next))

/* To store the curl output */
typedef struct afc_curl_output {
	char *data;
	size_t size;
} afc_curl_output_t;

/* Certification ID */
typedef struct afc_certification_Id {
	dll_t node;			/* self referencial (next,prev) pointers of type dll_t */
	char rulesetId[AFC_MAX_RULESET_ID];	/* Identifier of the regulatory rule */
	char id[AFC_MAX_CERT_ID];	/* This field represents the certification ID of an AP or
					 * Fixed Client Device
					*/
} afc_certification_Id_t;

/* Geographic coordinates */
typedef struct afc_point {
	double longitude;	/* longitude of the AP */
	double latitude;	/* latitude of the AP */
} afc_point_t;

/* check for Null Island (zero longitude and latitude: https://en.wikipedia.org/wiki/Null_Island */
#define AFC_IS_NULL_ISLAND(point)	((point)->longitude == AFC_DEF_LONGITUDE && \
		(point)->latitude == AFC_DEF_LATITUDE)

/* check validity of a location; checks ellipse latitude and longitude only for now */
#define AFC_CHECK_LOC(loc)		AFC_IS_NULL_ISLAND(&(loc)->ellipse.center)

/* List of Geographic coordinates */
typedef struct afc_points {
	dll_t node;		/* self referencial (next,prev) pointers of type dll_t */
	afc_point_t point;	/* Point object */
} afc_points_t;

/* Vectors object field */
typedef struct afc_vectors {
	dll_t node;	/* self referencial (next,prev) pointers of type dll_t */
	uint32 length;	/* distance in meters from a specified Point object */
	double angle;	/* direction of a vector in decimal degrees */
} afc_vectors_t;

/* Information of an AP */
typedef struct afc_device_descriptor {
	char serial_number[AFC_MAX_SERIAL_NUM];	/* Device serial number of an AP */
	afc_glist_t certification_Id;		/* List of type afc_certification_Id_t */
} afc_device_descriptor_t;

/* Description of the geographic area within which the AP or Fixed Client Device may operate,
 * including location uncertainty, described as an ellipse defined by the geographic coordinate of
 * its center and the lengths of its major and minor semi-axes
 */
typedef struct afc_ellipse {
	afc_point_t center;		/* geographic coordinates */
	uint32 major_axis;		/* length of the major semi axis of an ellipse within which
					 * the AP is located
					 */
	uint32 minor_axis;		/* length of the minor semi axis of an ellipse within which
					 * the AP is located
					 */
	float orientation;		/* represents the orientation of the majorAxis field in
					 * decimal degrees, measured clockwise from True North
					 */
} afc_ellipse_t;

/* geographic area within which the AP or Fixed Client Device is located */
typedef struct afc_radial_polygon {
	afc_point_t center;		/* geographic coordinates of the center point of a
					 * polygon
					 */
	afc_glist_t outer_boundary;	/* List of type afc_vectors_t. vertices of a polygon
					 * within which the AP or Fixed Client Device is located
					 */
} afc_radial_polygon_t;

/*  indicates the height, reference frame, and vertical uncertainty of the AP
 *  or Fixed Client Device antenna
 */
typedef struct afc_elevation {
	uint32 height;			/* hgt of the AP antenna in meters Above Ground Level(AGL),
					 * as measured relative to local ground level or height_type
					 * field AMSL, shall be given with respect to WGS84 datum
					*/
	char height_type[AFC_MAX_HT_TYPE_ID];	/* This field represents the reference level for the
						 * value of the height field. Allows AGL as measured
						 * relative to local ground level and
						 * AMSL(Above Mean Sea Level) value
						 */
	uint32 vertical_uncertainty;	/* vertical distance above and below the value of the height
					 * field within which AP or Fixed Client Device is located
					*/
} afc_elevation_t;

/* whether the deployment of the AP is located indoors, outdoor, or is unknown */
typedef enum afc_indoor_deployment {
	AFC_INDOOR_DEPLOYMENT_UNKNOWN = 0,
	AFC_INDOOR_DEPLOYMENT_INDOOR,
	AFC_INDOOR_DEPLOYMENT_OUTDOOR
} afc_indoor_deployment_t;

#define	AFC_LOCATION_FLAG_VALID		0x0001u /* Valid location is received from locpold */
#define	AFC_LOCATION_FLAG_USED		0x0002u /* Location is used for sending afc request */
/* Geographic area within which the AP or Fixed Client Device is located,
 * including location uncertainty
 */
typedef struct afc_location {
	afc_ellipse_t ellipse;				/* Description of the geographic area */
	afc_glist_t linear_polygon;			/* linear Polygon geographic area. List
							 * of type afc_points_t
							 */
	afc_radial_polygon_t radial_polygon;		/* RadialPolygon geographic area */
	afc_elevation_t elevation;			/* This field indicates height, reference
							 * frame and vertical uncertainty of the AP
							 * or Fixed Client Device antenna
							*/
	afc_indoor_deployment_t indoor_deployment;	/* deployment of the AP is located indoors,
							 * outdoor, or is unknown
							 */
	uint16 flags;					 /* flags of type AFC_LOCATION_FLAG_XYZ */
} afc_location_t;

/* Frequency range object fields */
typedef struct afc_freq_range {
	dll_t node;		/* self referencial (next,prev) pointers of type dll_t */
	uint32 low_frequency;	/* lowest frequency of the frequency range in MHz */
	uint32 high_frequency;	/* highest frequency of the frequency range in MHz */
} afc_freq_range_t;

/* Inquired Channels object fields */
typedef struct afc_inq_chans {
	dll_t node;		/* self referencial (next,prev) pointers of type dll_t */
	uint8 opclass;		/* global operating class */
	uint8 *chan_cfi;	/* Array of channel center frequency indices */
	uint8 chan_cfi_count;	/* Number of channel center frequency indices */
} afc_inq_chans_t;

/* Available Spectrum Inquiry Request for one or more APs */
typedef struct avl_spec_inq_req {
	dll_t node;				/* self referencial (next,prev) pointers of type
						 * dll_t
						 */
	char request_id[AFC_MAX_STR_REQ_ID];	/* Unique ID of the Available Spectrum Inquiry
						 * request
						 */
	afc_device_descriptor_t dev_desc;	/* Information of an AP */
	afc_location_t location;		/* Geographic area within which the AP or Fixed
						 * Client Device is located
						 */
	afc_location_t location_successive;	/* Locpold can notify afcd if it has better location
						 * fix, location_successive will be used store it.
						 */
	afc_glist_t inq_freq_range;		/* List of type afc_freq_range_t */
	afc_glist_t inq_chans;			/* List of type afc_inq_chans_t */
	int min_desired_pwr;			/* minimum desired EIRP in units of dBm */
	uint32 seq_no;				/* Sequence no */
} avl_spec_inq_req_t;

#define AFC_REQ_FLAG_USE_CACHED			0x0001u /* Determines the value of use_cached to
							 * be sent to locpold for location request.
							 */
#define AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS	0x0002u /* Indicates that afcd has started
							 * processing received location fix w.r.t
							 * its use in afc request to web server
							 * followed by sp gain check for valid
							 * response received from web server.
							 */

#define AFC_REQ_IS_USE_CACHED_SET(x)		((x) & AFC_REQ_FLAG_USE_CACHED)
#define AFC_REQ_IS_LOCATION_USE_IN_PROGRESS(x)	((x) & AFC_REQ_FLAG_LOCATION_USE_IN_PROGRESS)
/* Available Spectrum Inquiry Request message for one or more APs */
typedef struct avl_spec_inq_req_msg {
	uint16 flags;				/* Flags of type AFC_REQ_FLAGS_XYZ */
	int curl_wait_timeout;			/* Timeout for curl operation */
	char *base_url;				/* Base URL for request */
	char *tls_cacert;			/* Path to cacert bundle to use in curl TLS */
	char *mtls_cert;			/* Path to cert bundle to use in curl mTLS */
	char method[AFC_MAX_METHOD];		/* AFC Method */
	char req_version[AFC_MAX_VERSION];	/* Requests version */
	struct ether_addr al_mac;		/* IEEE1905 AL MAC address */
	int (*afc_get_lockpold_sock)();		/* Function pointer to fetch lockpold socket */
	/* Function pointer to process spectrum inquery request object */
	int (*afc_process_spec_inq_req_item)(avl_spec_inq_req_t *req_item);
	afc_glist_t spec_inq_req;		/* List of type avl_spec_inq_req_t Available
						 * Spectrum Inquiry Request list
						 */
} avl_spec_inq_req_msg_t;

/* Contains the maximum EIRP levels for each of the requested frequency ranges */
typedef struct afc_avl_freq_info {
	dll_t node;			/* self referencial (next,prev) pointers of type dll_t */
	afc_freq_range_t freq_range;	/* frequency range of the available spectrum */
	double max_psd;			/* maximum permissible EIRP available in any one MHz bin
					 * within the frequency range specified by the
					 * frequencyRange
					 */
} afc_avl_freq_info_t;

/* available channels and their corresponding maximum EIRP levels */
typedef struct afc_avl_chan_info {
	dll_t node;		/* self referencial (next,prev) pointers of type dll_t */
	uint8 opclass;		/* global operating class */
	uint8 *chan_cfi;	/* list of channel center frequency indices */
	uint8 chan_cfi_count;	/* Number of channel center frequency indices */
	double *max_eirp;	/* maximum permissible EIRP in units of dBm */
	uint8 max_eirp_count;	/* Number of maximum permissible EIRP */
} afc_avl_chan_info_t;

typedef struct afc_suppl_info {
	char (*mis_params)[AFC_MAX_FIELD_NAME];		/* list of names of missing parameter */
	uint8 mis_params_count;				/* Number of  missing parameter */
	char (*inv_params)[AFC_MAX_FIELD_NAME];		/* list of names of invalid parameter */
	uint8 inv_params_count;				/* Number of invalid parameter */
	char (*unexpected_params)[AFC_MAX_FIELD_NAME];	/* list of names of unexpected parameter */
	uint8 unexpected_params_count;			/* Number of unexpected parameter */
} afc_suppl_info_t;

typedef struct afc_response {
	int resp_code;				/* type of the response */
	char short_desc[AFC_MAX_RESP_DESCR];	/* short description of response code */
	afc_suppl_info_t suppl_info;		/* supplemental information that can help resolve
						 * failures
						 */
} afc_response_t;

/* Available Spectrum Inquiry Response for one or more APs */
typedef struct afc_avl_spec_inq_resp {
	dll_t node;			/* self referencial (next,prev) pointers of type dll_t */
	char request_id[AFC_MAX_STR_REQ_ID]; /* Unique ID of Available Spectrum Inquiry request */
	afc_glist_t avl_freq_info;	/* List of type afc_avl_freq_info_t */
	afc_glist_t avl_chan_info;	/* List of type afc_avl_chan_info_t */
	time_t avl_exp_tm;		/* time when the spectrum availability specified in the
					 * response expires
					 */
	afc_response_t response;	/* information on the outcome of the Available Spectrum
					 * Inquiry
					 */
} afc_avl_spec_inq_resp_t;

/* Flags used in afc_avl_spec_inq_resp_msg structure */
#define AFC_RESP_FLAGS_RESP_EXPIRED	0x01	/* Response is expired */

/* Check whether the Available Spectrum Inquiry response expired or not */
#define AFC_RESP_IS_RESP_EXPIRED(flags)	((flags) & (AFC_RESP_FLAGS_RESP_EXPIRED))

/* Available Spectrum Inquiry Response message */
typedef struct afc_avl_spec_inq_resp_msg {
	uint8 flags;				/* Flags of type AFC_RESP_FLAGS_XXX */
	char resp_version[AFC_MAX_VERSION];	/* Response version */
	afc_glist_t spec_inq_resp;		/* List of type avl_spec_inq_resp_t Available
						 * Spectrum Inquiry Response list
						 */
} afc_avl_spec_inq_resp_msg_t;

/* Read data from file. Returns number of elements read. Total size read will be
 * read_elements * (*size)
 */
size_t afc_read_file(char *filepath, char **data, size_t *size);

/* Write content to file */
void afc_write_to_file(char *filepath, char *data, size_t size);

/* Set the message level */
void afc_set_msglevel(uint32 msglevel);

/* Generic memory Allocation function for AFC app */
void* afc_malloc(uint32 len, int *error);

/* Initialize generic list */
void afc_glist_init(afc_glist_t *list);

/* Append a node to generic list */
void afc_glist_append(afc_glist_t *list, dll_t *new_obj);

/* Prepend a node to generic list */
void afc_glist_prepend(afc_glist_t *list, dll_t *new_obj);

/* Delete a node from generic list */
void afc_glist_delete(afc_glist_t *list, dll_t *obj);

/* Delete all the node from generic list */
int afc_glist_cleanup(afc_glist_t *list);

/* Count the number of entries in a space seperated list */
int afc_count_space_sep_list(char *list);

/* Post HTTPS request */
int afc_curl_send_request(avl_spec_inq_req_msg_t *spec_inq_req_msg, char *data,
	char *method, afc_curl_output_t *output);

/*
NAME
	afcerror -- map an error number to an error message string
SYNOPSIS
	const char* afcerrorstr(int afcerror)
DESCRIPTION
	Maps an errno number to an error message string.

	If the supplied error number is within the valid range of indices,
	but no message is available for the particular error number, or
	If the supplied error number is not a valid index into error_table
	then returns the string "Unknown Error NUM", where NUM is the
	error number.
*/
const char* afcerrorstr(int afcerror);

/* Read Available Spectrum Inquiry Request entries and store it in structure */
int afc_read_available_spectrum_inquiry_request(uint32 *request_id, int locpold_fd,
	avl_spec_inq_req_msg_t *spec_inq_req_msg);

/* Create and send Available Spectrum Inquiry Request */
int afc_perform_available_spectrum_inquiry_req(avl_spec_inq_req_msg_t *spec_inq_req_msg,
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg);

/* Read Available Spectrum Inquiry Response from file and store it in a structure */
int afc_read_available_spectrum_inquiry_response_from_file(
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg);

/* Cleanup Available Spectrum Inquiry request entries */
void afc_cleanup_available_spectrum_inquiry_request_list(avl_spec_inq_req_msg_t *spec_inq_req_msg);

/* Cleanup Available Spectrum Inquiry Response object */
void afc_cleanup_available_spectrum_inquiry_response_object(afc_avl_spec_inq_resp_t *spec_inq_resp);

/* Cleanup available channel info object */
void afc_cleanup_available_channel_info_object(afc_avl_chan_info_t *avl_chan_info);

/* Cleanup Available Spectrum Inquiry Response entries */
void afc_cleanup_available_spectrum_inquiry_response_list(
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg);

/* Creates json data from avl_spec_inq_req_msg_t structure. Free the returned data after use */
char *afc_json_data_from_request(avl_spec_inq_req_msg_t *spec_inq_req_msg);

/* Parse the JSON response data and store it in structure */
int afc_json_parse_response_data(char *data, size_t size,
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg);

/* AFC API to get the NVRAM value. */
char *afc_nvram_safe_get(const char *nvram);

/* AFC API to get the NVRAM value, if not found applies default value */
char *afc_nvram_safe_get_def(const char *nvram, char *def);

/* Gets the double val from NVARM, if not found applies the default value */
double afc_nvram_safe_get_double(char* prefix, const char *nvram, double def);

/* Gets the integer val from NVARM, if not found applies the default value */
int afc_nvram_safe_get_int(char* prefix, const char *nvram, int def);

/* Gets the unsigned integer val from NVARM, if not found applies the default value */
uint32 afc_nvram_safe_get_uint(char* prefix, const char *nvram, uint32 def);

/* Get the tiemout to perform Available Spectrum Inquiry Request */
uint32 afc_get_available_spectrum_inquiry_req_timeout(
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg);

/* Loop through Available Spectrum Inquiry Response entries and send to the driver */
int afc_consume_available_spectrum_inquiry_response(afc_avl_spec_inq_resp_msg_t
		*spec_inq_resp_msg);

/* Dump Available Spectrum Inquiry Response entries */
void afc_dump_available_spectrum_inquiry_response(afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg);

/* Create a json string with AFC request for WBD. Free the returned data after use */
char *afc_json_wbd_data_from_request(char *afc_req);

/* Create a json string with AFC response for WBD. Free the returned data after use */
char *afc_json_wbd_data_from_response(char *afc_resp, uint8 *al_mac);

/* Get the request_id from Available Spectrum Inquiry Request */
int afc_json_get_request_id_from_request(char *afc_req, char *request_id, int request_id_sz);

/* Update the request ID in the availableSpectrumInquiryResponses object and return the updated
 * JSON string. Free the returned data after use.
 */
char *afc_json_update_request_id_in_response(char *request_id, char *afc_resp);

/* Read Available Spectrum Inquiry Request entries and store it in structure */
void afc_read_frequency_range(avl_spec_inq_req_t *spec_inq_req);

/* Read inquired channels entries and store it in structure */
void afc_read_inquired_channels(avl_spec_inq_req_t *spec_inq_req);

/* check transmit power details from the driveer for AFC SP gains */
int afc_check_txpwr_max();
#endif /* _AFC_H_ */
