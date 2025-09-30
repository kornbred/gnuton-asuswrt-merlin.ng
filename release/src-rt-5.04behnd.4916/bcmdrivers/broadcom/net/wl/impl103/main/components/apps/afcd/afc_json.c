/*
 * AFC JSON format creation and parsing
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
 * $Id: afc_json.c 832722 2023-11-12 00:09:11Z $
 */

/* __USE_XOPEN and _GNU_SOURCE Used for strptime */
#define __USE_XOPEN
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <json.h>
#include <string.h>
#include <time.h>
#include "afc.h"
#include "afc_shared.h"

#define AFC_MODULE	"JSON"
#define AFC_STR_MAC_ADDR_LEN	18	/* Including NULL character */

#define JSON_SAFE_TOCKENER_PARSE(jobj_main, data, ERR, ret_val) \
		do { \
			jobj_main = json_tokener_parse(data); \
			if (jobj_main == NULL) { \
				AFC_ERROR("Main %s\n", afcerrorstr(ERR)); \
				return ret_val; \
			} \
		} while (0)

#define JSON_SAFE_GET_DATAOBJ(jobj_main, jobj_data, TAG, ERR) \
		do { \
			jobj_data = json_object_object_get(jobj_main, TAG); \
			if (jobj_data == NULL) { \
				AFC_ERROR("For Tag %s from >>%s<<: Data %s\n", TAG, \
						json_object_get_string(jobj_main), \
						afcerrorstr(ERR)); \
				ret = ERR; \
				goto end; \
			} \
		} while (0)

#define JSON_GET_DATAOBJ(jobj_main, jobj_data, TAG) \
		do { \
			jobj_data = json_object_object_get(jobj_main, TAG); \
		} while (0)

/* Gets the JSON string from JSON object and retruns the strrdup string */
static char*
afc_json_get_jsonstring_fm_object(json_object **jobj, int free_object)
{
	char* data = NULL;
	const char* strdata = NULL;
	AFC_ENTER();

	strdata = json_object_to_json_string(*jobj);

	if (strdata) {
		data = strdup(strdata);
		//printf("Data : %s\n", data);
	}
	if (free_object)
		json_object_put(*jobj);

	AFC_EXIT();
	return data;
}

/* Gets the String Value for the given tag name */
static int
afc_json_get_stringval_fm_tag(json_object *object, char *tag, char *buf, int buflen)
{
	int ret = AFCE_OK;
	const char *tmpval;
	json_object *object_tag;
	AFC_ENTER();

	memset(buf, 0, buflen);

	/* Validate arg */
	AFC_ASSERT_ARG(object, AFCE_JSON_NULL_OBJ);

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(object, object_tag, tag, AFCE_JSON_NULL_OBJ);

	tmpval = json_object_get_string(object_tag);
	if (tmpval)
		snprintf(buf, buflen, "%s", tmpval);

	if (strlen(buf) <= 0) {
		AFC_ERROR("%s for Tag[%s]\n", afcerrorstr(AFCE_JSON_INV_TAG_VAL), tag);
		ret = AFCE_JSON_INV_TAG_VAL;
		goto end;
	}

end:
	AFC_EXIT();
	return ret;
}

/* Gets the int Value for the given tag name */
static int
afc_json_get_intval_fm_tag(json_object *object, char *tag, int *tagval)
{
	int ret = AFCE_OK;
	json_object *object_tag;
	AFC_ENTER();

	/* Validate arg */
	AFC_ASSERT_ARG(object, AFCE_JSON_NULL_OBJ);

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(object, object_tag, tag, AFCE_JSON_NULL_OBJ);

	*tagval = json_object_get_int(object_tag);

end:
	AFC_EXIT();
	return ret;
}

/* Gets the double Value for the given tag name */
static int
afc_json_get_doubleval_fm_tag(json_object *object, char *tag, double *tagval)
{
	int ret = AFCE_OK;
	json_object *object_tag;
	AFC_ENTER();

	/* Validate arg */
	AFC_ASSERT_ARG(object, AFCE_JSON_NULL_OBJ);

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(object, object_tag, tag, AFCE_JSON_NULL_OBJ);

	*tagval = json_object_get_double(object_tag);

end:
	AFC_EXIT();
	return ret;
}

/* Converts binary MAC address to MAC string and adds it to object */
static void
afc_json_add_mac_to_object(json_object **object, char* tag, uint8 *mac)
{
	char tmpmac[AFC_STR_MAC_ADDR_LEN] = {0};
	AFC_ENTER();

	snprintf(tmpmac, sizeof(tmpmac), "%02x:%02x:%02x:%02x:%02x:%02x",
		mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
	json_object_object_add(*object, tag, json_object_new_string(tmpmac));

	AFC_EXIT();
}

/* Replace the string value with the new value for a given tag name */
static int
afc_json_replace_string_object(json_object *object, char *tag, char *buf)
{
	int ret = AFCE_OK;
	AFC_ENTER();

	/* Validate arg */
	AFC_ASSERT_ARG(object, AFCE_JSON_NULL_OBJ);

	json_object_object_del(object, tag);
	json_object_object_add(object, tag, json_object_new_string(buf));

end:
	AFC_EXIT();
	return ret;
}

/* Create a afc_cert object */
static json_object*
afc_json_generate_afc_cert_object(afc_certification_Id_t *afc_cert, json_object **jobj_afc_cert)
{
	AFC_ENTER();

	*jobj_afc_cert = json_object_new_object();
	json_object_object_add(*jobj_afc_cert, "rulesetId",
			json_object_new_string(afc_cert->rulesetId));
	json_object_object_add(*jobj_afc_cert, "id", json_object_new_string(afc_cert->id));

	AFC_EXIT();
	return (*jobj_afc_cert);
}

/* Create certificationId array and add it to parent object as "certificationId" name */
static void
afc_json_generate_certificationId_object(afc_device_descriptor_t *dev_desc,
	json_object *jobj_parent)
{

	json_object *jobj_afc_cert;
	json_object *jarr_certificationId;
	afc_certification_Id_t *certificationId;
	dll_t *certificationId_item_p;

	AFC_ENTER();

	jarr_certificationId = json_object_new_array();

	foreach_glist_item(certificationId_item_p, dev_desc->certification_Id) {
		certificationId = (afc_certification_Id_t*)certificationId_item_p;
		afc_json_generate_afc_cert_object(certificationId, &jobj_afc_cert);
		json_object_array_add(jarr_certificationId, jobj_afc_cert);
	}

	json_object_object_add(jobj_parent, "certificationId", jarr_certificationId);

	AFC_EXIT();
}

/* Create DeviceDescriptor object and add it to parent object as "deviceDescriptor" name */
static void
afc_json_generate_device_descriptor_object(afc_device_descriptor_t *dev_desc,
	json_object *jobj_parent)
{
	json_object *jobj_dev_des;
	AFC_ENTER();

	jobj_dev_des = json_object_new_object();
	json_object_object_add(jobj_dev_des, "serialNumber",
		json_object_new_string(dev_desc->serial_number));

	/* Generate and add certificationId object */
	afc_json_generate_certificationId_object(dev_desc, jobj_dev_des);

	json_object_object_add(jobj_parent, "deviceDescriptor", jobj_dev_des);

	AFC_EXIT();
}

/* Create a point object */
static json_object*
afc_json_generate_point_object(afc_point_t *point, json_object **jobj_point)
{
	AFC_ENTER();

	*jobj_point = json_object_new_object();
	json_object_object_add(*jobj_point, "longitude", json_object_new_double(point->longitude));
	json_object_object_add(*jobj_point, "latitude", json_object_new_double(point->latitude));

	AFC_EXIT();
	return (*jobj_point);
}

/* Create a vector object */
static json_object*
afc_json_generate_vector_object(afc_vectors_t *vector, json_object **jobj_vector)
{
	AFC_ENTER();

	*jobj_vector = json_object_new_object();
	json_object_object_add(*jobj_vector, "length", json_object_new_double(vector->length));
	json_object_object_add(*jobj_vector, "angle", json_object_new_double(vector->angle));

	AFC_EXIT();
	return (*jobj_vector);
}

/* Create center object and add it to parent object as "center" name */
static void
afc_json_generate_center_object(afc_point_t *center, json_object *jobj_parent)
{
	json_object *jobj_center;
	AFC_ENTER();

	afc_json_generate_point_object(center, &jobj_center);

	json_object_object_add(jobj_parent, "center", jobj_center);

	AFC_EXIT();
}

/* Create ellipse object and add it to parent object as "ellipse" name */
static void
afc_json_generate_ellipse_object(afc_ellipse_t *ellipse, json_object *jobj_parent)
{
	json_object *jobj_ellipse;
	AFC_ENTER();

	jobj_ellipse = json_object_new_object();

	/* Generate and add center object */
	afc_json_generate_center_object(&ellipse->center, jobj_ellipse);

	json_object_object_add(jobj_ellipse, "majorAxis",
		json_object_new_int(ellipse->major_axis));
	json_object_object_add(jobj_ellipse, "minorAxis",
		json_object_new_int(ellipse->minor_axis));
	json_object_object_add(jobj_ellipse, "orientation",
		json_object_new_int(ellipse->orientation));
	json_object_object_add(jobj_parent, "ellipse", jobj_ellipse);

	AFC_EXIT();
}

/* Create linearPolygon object and add it to parent object as "linearPolygon" name */
static void
afc_json_generate_linear_polygon_object(afc_location_t *location, json_object *jobj_parent)
{
	json_object *jarr_outer_boundary;
	json_object *jobj_point;
	json_object *jobj_outer_boundary;
	afc_points_t *outer_boundary;
	dll_t *outer_boundary_item_p;
	AFC_ENTER();

	if (location->linear_polygon.count <= 0) {
		AFC_INFO("Linear Ploygon not present\n");
		return;
	}

	jarr_outer_boundary = json_object_new_array();

	foreach_glist_item(outer_boundary_item_p, location->linear_polygon) {

		outer_boundary = (afc_points_t*)outer_boundary_item_p;

		afc_json_generate_point_object(&outer_boundary->point, &jobj_point);

		json_object_array_add(jarr_outer_boundary, jobj_point);
	}
	jobj_outer_boundary = json_object_new_object();
	json_object_object_add(jobj_outer_boundary, "outerBoundary", jarr_outer_boundary);

	json_object_object_add(jobj_parent, "linearPolygon", jobj_outer_boundary);

	AFC_EXIT();
}

/* Create radialPolygon object and add it to parent object as "radialPolygon" name */
static void
afc_json_generate_radial_polygon_object(afc_radial_polygon_t *radial_polygon,
	json_object *jobj_parent)
{
	json_object *jobj_radial_polygon;
	json_object *jobj_center;
	json_object *jobj_vector;
	json_object *jarr_outer_boundary;
	afc_vectors_t *outer_boundary;
	dll_t *outer_boundary_item_p;
	AFC_ENTER();

	if (radial_polygon->outer_boundary.count <= 0) {
		AFC_INFO("Radial Ploygon not present\n");
		return;
	}

	jobj_radial_polygon = json_object_new_object();

	afc_json_generate_point_object(&radial_polygon->center, &jobj_center);
	json_object_object_add(jobj_radial_polygon, "center", jobj_center);

	jarr_outer_boundary = json_object_new_array();

	foreach_glist_item(outer_boundary_item_p, radial_polygon->outer_boundary) {

		outer_boundary = (afc_vectors_t*)outer_boundary_item_p;

		afc_json_generate_vector_object(outer_boundary, &jobj_vector);

		json_object_array_add(jarr_outer_boundary, jobj_vector);
	}

	json_object_object_add(jobj_radial_polygon, "outerBoundary", jarr_outer_boundary);

	json_object_object_add(jobj_parent, "radialPolygon", jobj_radial_polygon);

	AFC_EXIT();
}

/* Create elevation object */
static void
afc_json_generate_elevation_object(afc_elevation_t *elevation, json_object *jobj_parent)
{
	json_object *jobj_elev;
	AFC_ENTER();

	jobj_elev = json_object_new_object();

	json_object_object_add(jobj_elev, "height", json_object_new_int(elevation->height));
	json_object_object_add(jobj_elev, "heightType",
		json_object_new_string(elevation->height_type));
	json_object_object_add(jobj_elev, "verticalUncertainty",
		json_object_new_int(elevation->vertical_uncertainty));
	json_object_object_add(jobj_parent, "elevation", jobj_elev);

	AFC_EXIT();
}

/* Create location object and add it to parent object as "location" name */
static void
afc_json_generate_location_object(afc_location_t *location, json_object *jobj_parent)
{
	json_object *jobj_loc;
	AFC_ENTER();

	jobj_loc = json_object_new_object();

	/* Generate and add ellipse object */
	afc_json_generate_ellipse_object(&location->ellipse, jobj_loc);

	/* Generate and add Linear Polygon object */
	afc_json_generate_linear_polygon_object(location, jobj_loc);

	/* Generate and add Radial Polygon object */
	afc_json_generate_radial_polygon_object(&location->radial_polygon, jobj_loc);

	/* Generate and add elevation object */
	afc_json_generate_elevation_object(&location->elevation, jobj_loc);

	json_object_object_add(jobj_loc, "indoorDeployment",
		json_object_new_int(location->indoor_deployment));
	json_object_object_add(jobj_parent, "location", jobj_loc);

	AFC_EXIT();
}

/* Create FrequencyRange object and add it to parent object array */
static void
afc_json_generate_frequency_object(afc_freq_range_t *inq_freq_range, json_object *jobj_parent)
{
	json_object *jobj_frequency;
	AFC_ENTER();

	jobj_frequency = json_object_new_object();
	json_object_object_add(jobj_frequency, "lowFrequency",
		json_object_new_int(inq_freq_range->low_frequency));
	json_object_object_add(jobj_frequency, "highFrequency",
		json_object_new_int(inq_freq_range->high_frequency));

	json_object_array_add(jobj_parent, jobj_frequency);

	AFC_EXIT();
}

/* Create inquiredFrequencyRange object and add it to parent object as "inquiredFrequencyRange"
 * name
 */
static void
afc_json_generate_inquired_frequency_range_array(avl_spec_inq_req_t *spec_inq_req,
	json_object *jobj_parent)
{
	json_object *jarr_inq_freq_range;
	afc_freq_range_t *inq_freq_range;
	dll_t *inq_freq_range_item_p;
	AFC_ENTER();

	if (spec_inq_req->inq_freq_range.count <= 0) {
		AFC_INFO("Frequency Range not present\n");
		goto end;
	}

	jarr_inq_freq_range = json_object_new_array();

	foreach_glist_item(inq_freq_range_item_p, spec_inq_req->inq_freq_range) {

		inq_freq_range = (afc_freq_range_t*)inq_freq_range_item_p;

		/* Generate and add Freqency Range */
		afc_json_generate_frequency_object(inq_freq_range, jarr_inq_freq_range);
	}

	json_object_object_add(jobj_parent, "inquiredFrequencyRange",
		jarr_inq_freq_range);

end:
	AFC_EXIT();
}

/* Create channelCfi array and add it to parent object as "channelCfi" name */
static void
afc_json_generate_channel_cfi_array(json_object *jobj_parent, afc_inq_chans_t *inq_chans)
{
	int i;
	json_object *jarr_channel_cfi;
	AFC_ENTER();

	jarr_channel_cfi = json_object_new_array();

	for (i = 0; i < inq_chans->chan_cfi_count; i++) {
		json_object_array_add(jarr_channel_cfi,
			json_object_new_int(inq_chans->chan_cfi[i]));
	}

	json_object_object_add(jobj_parent, "channelCfi", jarr_channel_cfi);

	AFC_EXIT();
}

/* Create Channels object and add it to parent object array */
static void
afc_json_generate_global_opclass_object(json_object *jobj_parent, afc_inq_chans_t *inq_chans)
{
	json_object *jobj_opclass_chan;
	AFC_ENTER();

	jobj_opclass_chan = json_object_new_object();
	json_object_object_add(jobj_opclass_chan, "globalOperatingClass",
		json_object_new_int(inq_chans->opclass));

	if (inq_chans->chan_cfi_count > 0) {
		/* Generate and add channel cfi array */
		afc_json_generate_channel_cfi_array(jobj_opclass_chan, inq_chans);
	}

	json_object_array_add(jobj_parent, jobj_opclass_chan);

	AFC_EXIT();
}

/* Create inquiredChannels array and add it to parent object as "inquiredChannels" name */
static void
afc_json_generate_inquired_channels_array(avl_spec_inq_req_t *spec_inq_req,
	json_object *jobj_parent)
{
	json_object *jarr_inq_chan;
	afc_inq_chans_t *inq_chans;
	dll_t *inq_chans_item_p;
	AFC_ENTER();

	if (spec_inq_req->inq_chans.count <= 0) {
		AFC_INFO("Inquired Channels not present\n");
		goto end;
	}

	jarr_inq_chan = json_object_new_array();

	foreach_glist_item(inq_chans_item_p, spec_inq_req->inq_chans) {

		inq_chans = (afc_inq_chans_t*)inq_chans_item_p;

		afc_json_generate_global_opclass_object(jarr_inq_chan, inq_chans);
	}

	json_object_object_add(jobj_parent, "inquiredChannels", jarr_inq_chan);

end:
	AFC_EXIT();
}

/* Create AvailableSpectrumInquiryRequest object and add it to parent object array */
static void
afc_json_available_spectrum_inquiry_requests_object(avl_spec_inq_req_t *spec_inq_req,
	json_object *jobj_parent)
{
	json_object *jobj_inq_req;
	uint8 afc_inq_type;
	AFC_ENTER();

	/* Get NVRAM : AFC inquiry type(s) */
	afc_inq_type = (uint8)afc_nvram_safe_get_int(NULL, AFC_NVRAM_INQ_TYPE, AFC_DEF_INQ_TYPE);

	jobj_inq_req = json_object_new_object();
	json_object_object_add(jobj_inq_req, "requestId",
		json_object_new_string(spec_inq_req->request_id));

	/* Generate and add deviceDescriptor */
	afc_json_generate_device_descriptor_object(&spec_inq_req->dev_desc, jobj_inq_req);

	/* Generate and add location object.
	 * On consuming location_successive data, reset flags for location obj so that any new
	 * location fix from locpold will be stored in it. Similarly reset the consumed
	 * location_successive objects flag while consuming location object.
	 */
	if ((spec_inq_req->location.flags & AFC_LOCATION_FLAG_VALID) &&
			!(spec_inq_req->location.flags & AFC_LOCATION_FLAG_USED)) {
		afc_json_generate_location_object(&spec_inq_req->location, jobj_inq_req);
		spec_inq_req->location.flags |= AFC_LOCATION_FLAG_USED;
		if (spec_inq_req->location_successive.flags & AFC_LOCATION_FLAG_USED) {
			spec_inq_req->location_successive.flags = 0;
		}
	} else if ((spec_inq_req->location_successive.flags & AFC_LOCATION_FLAG_VALID) &&
			!(spec_inq_req->location_successive.flags & AFC_LOCATION_FLAG_USED)) {
		afc_json_generate_location_object(&spec_inq_req->location_successive, jobj_inq_req);
		spec_inq_req->location_successive.flags |= AFC_LOCATION_FLAG_USED;
		spec_inq_req->location.flags = 0;
	} else {
		AFC_ERROR("Both location and location_successive are used at least once to "
				"generate afc request to afc web server location_flags 0x%x "
				"location_successive_flags 0x%x\n", spec_inq_req->location.flags,
				spec_inq_req->location_successive.flags);
		goto end;
	}

	if ((afc_inq_type & AFC_INQ_TYPE_FREQ) != 0) {
		/* Generate and add inquiredFrequencyRange array */
		afc_json_generate_inquired_frequency_range_array(spec_inq_req, jobj_inq_req);
	}

	if ((afc_inq_type & AFC_INQ_TYPE_CHAN) != 0) {
		/* Generate and add inquiredChannels array */
		afc_json_generate_inquired_channels_array(spec_inq_req, jobj_inq_req);
	}

	if (spec_inq_req->min_desired_pwr > 0) {
		json_object_object_add(jobj_inq_req, "minDesiredPower",
			json_object_new_int(spec_inq_req->min_desired_pwr));
	}

	json_object_array_add(jobj_parent, jobj_inq_req);

end:
	AFC_EXIT();
}

/* Create AvailableSpectrumInquiryRequest array and add it to parent object
 * "availableSpectrumInquiryRequests" name
 */
static void
afc_json_available_spectrum_inquiry_requests_array(avl_spec_inq_req_t *spec_inq_req,
	json_object *jobj_parent)
{
	json_object *jarr_inq_req;
	AFC_ENTER();

	jarr_inq_req = json_object_new_array();

	/* Generate and add availableSpectrumInquiryRequests object */
	afc_json_available_spectrum_inquiry_requests_object(spec_inq_req, jarr_inq_req);

	json_object_object_add(jobj_parent, "availableSpectrumInquiryRequests",
		jarr_inq_req);

	AFC_EXIT();
}

/* Create a json string for Available Spectrum Inquiry Request Message */
char*
afc_json_data_from_request(avl_spec_inq_req_msg_t *spec_inq_req_msg)
{
	json_object *jobj_main;
	avl_spec_inq_req_t *spec_inq_req = NULL;
	dll_t *spec_inq_req_item_p;
	AFC_ENTER();

	AFC_INFO("Generate JSON data to send it to the AFC System\n");

	jobj_main = json_object_new_object();

	json_object_object_add(jobj_main, "version",
		json_object_new_string(spec_inq_req_msg->req_version));

	foreach_glist_item(spec_inq_req_item_p, spec_inq_req_msg->spec_inq_req) {

		spec_inq_req = (avl_spec_inq_req_t*)spec_inq_req_item_p;

		/* Generate and add availableSpectrumInquiryRequests array */
		afc_json_available_spectrum_inquiry_requests_array(spec_inq_req, jobj_main);
	}

	AFC_EXIT();
	return afc_json_get_jsonstring_fm_object(&jobj_main, 1);
}

/* Parse FrequencyRange object */
static int
afc_json_parse_frequency_range(afc_freq_range_t *freq_range, json_object *jobj_freq_range)
{
	int ret = AFCE_OK;
	AFC_ENTER();

	ret = afc_json_get_intval_fm_tag(jobj_freq_range, "lowFrequency",
		(int*)&freq_range->low_frequency);
	AFC_ASSERT();

	afc_json_get_intval_fm_tag(jobj_freq_range, "highFrequency",
		(int*)&freq_range->high_frequency);
	AFC_ASSERT();

	AFC_DEBUG("Lowest frequency of the frequency range in MHz: %d "
		"Highest frequency of the frequency range in MHz: %d\n",
		freq_range->low_frequency, freq_range->high_frequency);

end:
	AFC_EXIT();
	return ret;
}

/* Parse AvailableFrequencyInfo object */
static int
afc_json_parse_available_frequency_info(afc_avl_spec_inq_resp_t *spec_inq_resp,
	json_object *jobj_avl_freq_info)
{
	int ret = AFCE_OK;
	afc_avl_freq_info_t *avl_freq_info = NULL;
	json_object *jobj_freq_range;
	AFC_ENTER();

	/* Allocate availableFrequencyInfo structure */
	avl_freq_info = (afc_avl_freq_info_t*)afc_malloc(sizeof(*avl_freq_info), &ret);
	AFC_ASSERT();

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(jobj_avl_freq_info, jobj_freq_range, "frequencyRange",
		AFCE_JSON_NULL_OBJ);
	ret = afc_json_parse_frequency_range(&avl_freq_info->freq_range, jobj_freq_range);
	AFC_ASSERT();

	ret = afc_json_get_doubleval_fm_tag(jobj_avl_freq_info, "maxPsd", &avl_freq_info->max_psd);
	AFC_ASSERT();
	AFC_DEBUG("Maximum permissible PSD available: %f\n", avl_freq_info->max_psd);

	/* In the end, Add this new Allocate availableFrequencyInfo item to list */
	afc_glist_append(&spec_inq_resp->avl_freq_info, (dll_t *)avl_freq_info);

end:
	if ((ret != AFCE_OK) && avl_freq_info) {
		free(avl_freq_info);
	}
	AFC_EXIT();
	return ret;
}

/* Parse channelCfi array */
static int
afc_json_parse_channel_cfi(afc_avl_chan_info_t *avl_chan_info, json_object *jobj_avl_chan_info)
{
	int ret = AFCE_OK, count = 0, i;
	json_object *jarr_chan_cfi;
	json_object *jobj_chan_cfi;
	AFC_ENTER();

	JSON_SAFE_GET_DATAOBJ(jobj_avl_chan_info, jarr_chan_cfi, "channelCfi", AFCE_JSON_NULL_OBJ);
	count = json_object_array_length(jarr_chan_cfi);
	AFC_DEBUG("Number of channel center frequency indices %d\n", count);

	avl_chan_info->chan_cfi = (uint8*)afc_malloc(count * sizeof(uint8), &ret);
	AFC_ASSERT_MSG("Failed to allocate channel center frequency indices array\n");

	for (i = 0; i < count; i++) {
		jobj_chan_cfi = json_object_array_get_idx(jarr_chan_cfi, i);
		if (jobj_chan_cfi == NULL)
			goto end;

		avl_chan_info->chan_cfi[avl_chan_info->chan_cfi_count] =
			(uint8)json_object_get_int(jobj_chan_cfi);
		AFC_DEBUG("Index: %d channel center frequency indices: %d\n",
			avl_chan_info->chan_cfi_count,
			avl_chan_info->chan_cfi[avl_chan_info->chan_cfi_count]);
		avl_chan_info->chan_cfi_count++;
	}

end:
	AFC_EXIT();
	return ret;
}

/* Parse maxEirp array */
static int
afc_json_parse_max_eirp(afc_avl_chan_info_t *avl_chan_info, json_object *jobj_avl_chan_info)
{
	int ret = AFCE_OK, count = 0, i;
	json_object *jarr_max_eirp;
	json_object *jobj_max_eirp;
	AFC_ENTER();

	JSON_SAFE_GET_DATAOBJ(jobj_avl_chan_info, jarr_max_eirp, "maxEirp", AFCE_JSON_NULL_OBJ);
	count = json_object_array_length(jarr_max_eirp);
	AFC_DEBUG("Number of maximum permissible EIRP %d\n", count);

	avl_chan_info->max_eirp = (double*)afc_malloc(count * sizeof(double), &ret);
	AFC_ASSERT_MSG("Failed to allocate maximum permissible EIRP array\n");

	for (i = 0; i < count; i++) {
		jobj_max_eirp = json_object_array_get_idx(jarr_max_eirp, i);
		if (jobj_max_eirp == NULL)
			goto end;

		avl_chan_info->max_eirp[avl_chan_info->max_eirp_count] =
			(double)json_object_get_double(jobj_max_eirp);
		AFC_DEBUG("Index: %d maximum permissible EIRP: %f\n", avl_chan_info->max_eirp_count,
			avl_chan_info->max_eirp[avl_chan_info->max_eirp_count]);
		avl_chan_info->max_eirp_count++;
	}

end:
	AFC_EXIT();
	return ret;
}

/* Parse AvailableChannelInfo object */
static int
afc_json_parse_available_channel_info(afc_avl_spec_inq_resp_t *spec_inq_resp,
	json_object *jobj_avl_chan_info)
{
	int ret = AFCE_OK;
	afc_avl_chan_info_t *avl_chan_info = NULL;
	int opclass;
	AFC_ENTER();

	/* Allocate availableChannelInfo structure */
	avl_chan_info = (afc_avl_chan_info_t*)afc_malloc(sizeof(*avl_chan_info), &ret);
	AFC_ASSERT();

	/* Get Data object */
	ret = afc_json_get_intval_fm_tag(jobj_avl_chan_info, "globalOperatingClass", &opclass);
	AFC_ASSERT();
	avl_chan_info->opclass = (uint8)opclass;
	AFC_DEBUG("Global operating class: %d\n", avl_chan_info->opclass);

	ret = afc_json_parse_channel_cfi(avl_chan_info, jobj_avl_chan_info);
	AFC_ASSERT();

	ret = afc_json_parse_max_eirp(avl_chan_info, jobj_avl_chan_info);
	AFC_ASSERT();

	/* In the end, Add this new Allocate availableChannelInfo item to list */
	afc_glist_append(&spec_inq_resp->avl_chan_info, (dll_t *)avl_chan_info);

end:
	if ((ret != AFCE_OK) && avl_chan_info) {
		afc_cleanup_available_channel_info_object(avl_chan_info);
		free(avl_chan_info);
	}
	AFC_EXIT();
	return ret;
}

/* Parse Response object */
static void
afc_json_parse_response_object(afc_response_t *response, json_object *jobj_response)
{
	int ret = AFCE_OK;
	AFC_ENTER();

	ret = afc_json_get_intval_fm_tag(jobj_response, "responseCode", &response->resp_code);
	AFC_ASSERT();
	AFC_DEBUG("Type of the response %d\n", response->resp_code);

	ret = afc_json_get_stringval_fm_tag(jobj_response, "shortDescription",
		response->short_desc, sizeof(response->short_desc));
	AFC_ASSERT();
	AFC_DEBUG("Short description of the response: %s\n", response->short_desc);

end:
	AFC_EXIT();
	return;
}

/* Parse AvailableSpectrumInquiryResponse object */
static int
afc_json_parse_available_spectrum_inquiry_response(afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg,
	json_object *jobj_inq_resp)
{
	int ret = AFCE_OK, count = 0, i;
	afc_avl_spec_inq_resp_t *spec_inq_resp = NULL;
	json_object *jarr_avl_freq_info = NULL;
	json_object *jobj_avl_freq_info;
	json_object *jarr_avl_chan_info;
	json_object *jobj_avl_chan_info;
	json_object *jobj_response;
	struct tm ts = {0};
	time_t cur_time;
	char avl_exp_tm[AFC_MAX_TM];
	AFC_ENTER();

	/* Allocate Available Spectrum Inquiry Request structure */
	spec_inq_resp = (afc_avl_spec_inq_resp_t*)afc_malloc(sizeof(*spec_inq_resp), &ret);
	AFC_ASSERT();

	afc_glist_init(&spec_inq_resp->avl_freq_info);
	afc_glist_init(&spec_inq_resp->avl_chan_info);

	ret = afc_json_get_stringval_fm_tag(jobj_inq_resp, "requestId",
		spec_inq_resp->request_id, sizeof(spec_inq_resp->request_id));
	AFC_ASSERT();
	AFC_DEBUG("Request ID: %s\n", spec_inq_resp->request_id);

	JSON_SAFE_GET_DATAOBJ(jobj_inq_resp, jobj_response, "response", AFCE_JSON_NULL_OBJ);
	afc_json_parse_response_object(&spec_inq_resp->response, jobj_response);

	/* All below fields available only if the Response Code indicates SUCCESS */
	if (spec_inq_resp->response.resp_code != 0) {
		AFC_WARNING("Response code is not success, exiting from this response object\n");
		ret = AFCE_FAIL;
		goto end;
	}

	/* Get Data object which is not mandatory */
	JSON_GET_DATAOBJ(jobj_inq_resp, jarr_avl_freq_info, "availableFrequencyInfo");
	if (jarr_avl_freq_info) {
		count = json_object_array_length(jarr_avl_freq_info);
		AFC_DEBUG("Number of Available Frequency Info: %d\n", count);

		for (i = 0; i < count; i++) {
			jobj_avl_freq_info = json_object_array_get_idx(jarr_avl_freq_info, i);
			if (jobj_avl_freq_info == NULL) {
				ret = AFCE_FAIL;
				goto end;
			}

			afc_json_parse_available_frequency_info(spec_inq_resp, jobj_avl_freq_info);
		}
	} else {
		AFC_DEBUG("Available Frequency Info object not present\n");
	}

	/* Get Data object which is not mandatory */
	JSON_GET_DATAOBJ(jobj_inq_resp, jarr_avl_chan_info, "availableChannelInfo");
	if (jarr_avl_chan_info) {
		count = json_object_array_length(jarr_avl_chan_info);
		AFC_DEBUG("Number of Available Channel Info %d\n", count);

		for (i = 0; i < count; i++) {
			jobj_avl_chan_info = json_object_array_get_idx(jarr_avl_chan_info, i);
			if (jobj_avl_chan_info == NULL) {
				ret = AFCE_FAIL;
				goto end;
			}

			afc_json_parse_available_channel_info(spec_inq_resp, jobj_avl_chan_info);
		}
	} else {
		AFC_DEBUG("Available Channel Info object not present\n");
	}

	ret = afc_json_get_stringval_fm_tag(jobj_inq_resp, "availabilityExpireTime",
		avl_exp_tm, sizeof(avl_exp_tm));
	AFC_ASSERT();

	/* Convert the time in string(FORMAT: YYYY-MM-DDThh:mm:ssZ) to time_t */
	strptime(avl_exp_tm, "%FT%T%z", &ts);
	spec_inq_resp->avl_exp_tm = mktime(&ts);	/* timezone is not used by mktime */
	spec_inq_resp->avl_exp_tm += ts.tm_gmtoff;	/* account for the timezone */

	cur_time = time(NULL);
	AFC_DEBUG("Time when the spectrum availability specified in the response expires: %s. "
		"time_t %lu Current time %lu. gmtoff:%ld\n", avl_exp_tm,
		(unsigned long)(spec_inq_resp->avl_exp_tm), (unsigned long)(cur_time),
		ts.tm_gmtoff);

	if (spec_inq_resp->avl_exp_tm < cur_time) {
		spec_inq_resp_msg->flags |= AFC_RESP_FLAGS_RESP_EXPIRED;
		AFC_INFO("spectrum availability specified in this response has expired %lu "
			"seconds ago. spec_inq_resp->avl_exp_tm[%lu] < cur_time[%lu]\n",
			(unsigned long)(cur_time - spec_inq_resp->avl_exp_tm),
			(unsigned long)(spec_inq_resp->avl_exp_tm),
			(unsigned long)(cur_time));
	} else {
		AFC_INFO("spectrum availability specified in this response will expire in another "
			"%lu seconds\n",
			(unsigned long)(spec_inq_resp->avl_exp_tm - cur_time));
	}

	/* In the end, Add this newly Allocated Available Spectrum Inquiry Response item to list */
	afc_glist_append(&spec_inq_resp_msg->spec_inq_resp, (dll_t *)spec_inq_resp);
	ret = AFCE_OK;
end:

	if ((ret != AFCE_OK) && spec_inq_resp) {
		afc_cleanup_available_spectrum_inquiry_response_object(spec_inq_resp);
		free(spec_inq_resp);
	}

	AFC_EXIT();
	return ret;
}

/* Parse the availableSpectrumInquiryResponses object */
int
afc_json_parse_response_data(char *data, size_t size,
	afc_avl_spec_inq_resp_msg_t *spec_inq_resp_msg)
{
	int ret = AFCE_OK, count = 0, i;
	json_object *jobj_main;
	json_object *jarr_inq_resp;
	json_object *jobj_inq_resp;
	AFC_ENTER();

	AFC_INFO("Parse the JSON response\n");

	/* Load Main object fm string data */
	JSON_SAFE_TOCKENER_PARSE(jobj_main, data, AFCE_JSON_NULL_OBJ, AFCE_JSON_NULL_OBJ);

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(jobj_main, jarr_inq_resp, "availableSpectrumInquiryResponses",
		AFCE_JSON_NULL_OBJ);

	ret = afc_json_get_stringval_fm_tag(jobj_main, "version", spec_inq_resp_msg->resp_version,
		sizeof(spec_inq_resp_msg->resp_version));
	AFC_ASSERT();
	AFC_DEBUG("version Number: %s\n", spec_inq_resp_msg->resp_version);

	count = json_object_array_length(jarr_inq_resp);
	AFC_DEBUG("Number of Available Spectrum Inquiry Responses: %d\n", count);
	/* If the count is 0, no need to move further */
	AFC_ASSERT_ARG(count, AFCE_JSON_NULL_OBJ);

	/* Cleanup if present */
	afc_cleanup_available_spectrum_inquiry_response_list(spec_inq_resp_msg);

	afc_glist_init(&spec_inq_resp_msg->spec_inq_resp);

	for (i = 0; i < count; i++) {
		jobj_inq_resp = json_object_array_get_idx(jarr_inq_resp, i);
		if (jobj_inq_resp == NULL)
			goto end;

		afc_json_parse_available_spectrum_inquiry_response(spec_inq_resp_msg,
			jobj_inq_resp);
	}

end:
	json_object_put(jobj_main);

	AFC_EXIT();
	return ret;
}

/* JSON Creation and Parsing for the AFC SmartMesh Integration */

/* Create a json string with AFC request for WBD */
char*
afc_json_wbd_data_from_request(char *afc_req)
{
	json_object *jobj_main;
	AFC_ENTER();

	AFC_INFO("Generate JSON with AFC Request data to send it to the WBD\n");

	jobj_main = json_object_new_object();

	json_object_object_add(jobj_main, "Cmd",
		json_object_new_string("afc"));

	json_object_object_add(jobj_main, "SubCmd",
		json_object_new_string("afc_req"));

	json_object_object_add(jobj_main, "CMDData",
		json_object_new_string(afc_req));

	AFC_EXIT();
	return afc_json_get_jsonstring_fm_object(&jobj_main, 1);
}

/* Create a json string with AFC response for WBD. Free the returned data after use */
char*
afc_json_wbd_data_from_response(char *afc_resp, uint8 *al_mac)
{
	json_object *jobj_main;
	AFC_ENTER();

	AFC_INFO("Generate JSON with AFC response data to send it to the WBD\n");

	jobj_main = json_object_new_object();

	json_object_object_add(jobj_main, "Cmd",
		json_object_new_string("afc"));

	json_object_object_add(jobj_main, "SubCmd",
		json_object_new_string("afc_resp"));

	afc_json_add_mac_to_object(&jobj_main, "ALMAC", al_mac);

	json_object_object_add(jobj_main, "CMDData",
		json_object_new_string(afc_resp));

	AFC_EXIT();
	return afc_json_get_jsonstring_fm_object(&jobj_main, 1);
}

/* Get the request_id from Available Spectrum Inquiry Request */
int
afc_json_get_request_id_from_request(char *afc_req, char *request_id, int request_id_sz)
{
	int ret = AFCE_OK, count = 0;
	json_object *jobj_main;
	json_object *jarr_inq_req;
	json_object *jobj_inq_req;
	AFC_ENTER();

	AFC_INFO("Parse the JSON request to get the Request ID\n");

	/* Load Main object fm string data */
	JSON_SAFE_TOCKENER_PARSE(jobj_main, afc_req, AFCE_JSON_NULL_OBJ, AFCE_JSON_NULL_OBJ);

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(jobj_main, jarr_inq_req, "availableSpectrumInquiryRequests",
		AFCE_JSON_NULL_OBJ);

	count = json_object_array_length(jarr_inq_req);
	AFC_DEBUG("Number of Available Spectrum Inquiry Requests: %d\n", count);
	/* If the count is 0, no need to move further */
	AFC_ASSERT_ARG(count, AFCE_JSON_NULL_OBJ);

	/* Just get the 0th array object and get the RequestID from it */
	jobj_inq_req = json_object_array_get_idx(jarr_inq_req, 0);
	if (jobj_inq_req == NULL) {
		AFC_ERROR("availableSpectrumInquiryRequest object at index 0 is NULL\n");
		goto end;
	}

	ret = afc_json_get_stringval_fm_tag(jobj_inq_req, "requestId",
		request_id, request_id_sz);
	AFC_ASSERT();
	AFC_DEBUG("Request ID: %s\n", request_id);

end:
	json_object_put(jobj_main);

	AFC_EXIT();
	return ret;
}

/* Update the request ID in the availableSpectrumInquiryResponses object and return the updated
 * JSON string
 */
char*
afc_json_update_request_id_in_response(char *request_id, char *afc_resp)
{
	int ret = AFCE_OK, count = 0, i;
	json_object *jobj_main = NULL;
	json_object *jarr_inq_resp;
	json_object *jobj_inq_resp;
	AFC_ENTER();

	AFC_INFO("Parse the JSON availableSpectrumInquiryResponse to update the Request ID\n");

	/* Load Main object fm string data */
	jobj_main = json_tokener_parse(afc_resp);
	if (jobj_main == NULL) {
		ret = AFCE_JSON_NULL_OBJ;
		AFC_ERROR("Main %s\n", afcerrorstr(AFCE_JSON_NULL_OBJ));
		goto end;
	}

	/* Get Data object */
	JSON_SAFE_GET_DATAOBJ(jobj_main, jarr_inq_resp, "availableSpectrumInquiryResponses",
		AFCE_JSON_NULL_OBJ);

	count = json_object_array_length(jarr_inq_resp);
	AFC_DEBUG("Number of Available Spectrum Inquiry Responses: %d\n", count);
	/* If the count is 0, no need to move further */
	AFC_ASSERT_ARG(count, AFCE_JSON_NULL_OBJ);

	for (i = 0; i < count; i++) {
		char old_request_id[AFC_MAX_STR_REQ_ID];

		jobj_inq_resp = json_object_array_get_idx(jarr_inq_resp, i);
		if (jobj_inq_resp == NULL) {
			AFC_ERROR("availableSpectrumInquiryResponse object at index %d is NULL\n",
				i);
			goto end;
		}

		ret = afc_json_get_stringval_fm_tag(jobj_inq_resp, "requestId",
			old_request_id, sizeof(old_request_id));
		AFC_ASSERT();

		AFC_DEBUG("Update Old Request ID: %s with the new Request ID: %s\n",
			old_request_id, request_id);
		afc_json_replace_string_object(jobj_inq_resp, "requestId", request_id);
	}

end:

	AFC_EXIT();
	if (ret == AFCE_OK) {
		return afc_json_get_jsonstring_fm_object(&jobj_main, 1);
	} else if (jobj_main) {
		json_object_put(jobj_main);
	}

	return NULL;
}
