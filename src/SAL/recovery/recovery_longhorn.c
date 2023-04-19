// SPDX-License-Identifier: LGPL-3.0-or-later
/*
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 3 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc.,
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

#include "config.h"
#include "log.h"
#include "nfs_core.h"
#include "nfs4.h"
#include "sal_functions.h"
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
#include <ctype.h>
#include <string.h>
#include <netdb.h>
#include "bsd-base64.h"
#include "client_mgr.h"
#include "fsal.h"
#include "common_utils.h"
#include <libgen.h>
#include <curl/curl.h>
#include <json-c/json.h>

#define VERSION_BYTES 8
#define URL_MAX       2048
#define PAYLOAD_MAX   2048
#define LONGHORN_RECOVERY_BACKEND_URL "http://longhorn-recovery-backend:9503/v1/recoverybackend"

static char recov_version[NAME_MAX];
static pthread_rwlock_t recov_lock = PTHREAD_RWLOCK_INITIALIZER;

typedef enum {
	HTTP_GET = 0,
	HTTP_POST,
	HTTP_PUT,
	HTTP_DELETE,
} HTTP_METHOD;

struct http_result {
	void *memory;
	size_t size;
};

static char *generate_random_string(const int len)
{
	static const char alphanum[] =
		"0123456789"
		"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
	char *buf;

	buf = malloc(len + 1);
	if (!buf) {
		return NULL;
	}

	for (int i = 0; i < len; ++i) {
		buf[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}

	buf[len] = '\0';

	return buf;
}

static size_t callback_write_result(void *contents, size_t size, size_t nmemb, void *userp)
{
	char *buf = NULL;
	size_t real_size = size * nmemb;

	if (contents != NULL && userp) {
		struct http_result *mem = (struct http_result *) userp;
		buf = realloc(mem->memory, mem->size + real_size + 1);
		if (buf) {
			mem->memory = buf;
			memcpy(&(((unsigned char *)mem->memory)[mem->size]), contents, real_size);
			mem->size += real_size;
			return real_size;
		}
	}
	return 0;
}

static int http_call(HTTP_METHOD method, const char *url, char *payload, size_t payload_size, char **output, size_t *output_size)
{
	int result = -1;
	struct http_result buffer = {.memory = NULL, .size = 0};
	CURL *handle = NULL;
	CURLcode curl_result = 0;
	struct curl_slist *curl_headers = NULL;
	char *encoded_url = NULL;
	long http_code = 0;

	if (method < HTTP_GET || method > HTTP_DELETE) {
		LogEvent(COMPONENT_CLIENTID, "Invalid method: %d", method);
		goto error;
	}

	if (!url) {
		LogEvent(COMPONENT_CLIENTID, "url is NULL");
		goto error;
	}

	/* Initialize CURL handle */
	handle = curl_easy_init();
	if (!handle) {
		LogEvent(COMPONENT_CLIENTID, "Failed to initialize CURL");
		goto error;
	}

	/* Set CURL options */
	curl_result = curl_easy_setopt(handle, CURLOPT_URL, url);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_FOLLOWLOCATION, 1L);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_WRITEFUNCTION, callback_write_result);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_WRITEDATA, (void *)&buffer);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_USERAGENT, "libcurl-agent/1.0");
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	switch (method) {
		case HTTP_GET:
			curl_result = curl_easy_setopt(handle, CURLOPT_HTTPGET, 1L);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}
			break;
		case HTTP_POST:
			curl_result = curl_easy_setopt(handle, CURLOPT_POST, 1L);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, payload_size);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			break;
		case HTTP_PUT:
			curl_result = curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "PUT");
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDS, payload);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			curl_result = curl_easy_setopt(handle, CURLOPT_POSTFIELDSIZE, payload_size);
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}

			break;
		case HTTP_DELETE:
			curl_result = curl_easy_setopt(handle, CURLOPT_CUSTOMREQUEST, "DELETE");
			if (curl_result != CURLE_OK) {
				LogEvent(COMPONENT_CLIENTID, "Failed to set CURL option: %s", curl_easy_strerror(curl_result));
				goto error;
			}
	}

	/* Set HTTP headers */
	curl_headers = curl_slist_append(curl_headers, "Accept: application/json");
	if (!curl_headers) {
		LogEvent(COMPONENT_CLIENTID, "Failed to construct CURL headers");
		goto error;
	}

	curl_headers = curl_slist_append(curl_headers, "Content-Type: application/json; charset=utf-8");
	if (!curl_headers) {
		LogEvent(COMPONENT_CLIENTID, "Failed to construct CURL headers");
		goto error;
	}

	curl_headers = curl_slist_append(curl_headers, "Connection: close");
	if (!curl_headers) {
		LogEvent(COMPONENT_CLIENTID, "Failed to construct CURL headers");
		goto error;
	}

	curl_result = curl_easy_setopt(handle, CURLOPT_HTTPHEADER, curl_headers);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to set CURL headers: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	/* Make HTTP request */
	curl_result = curl_easy_perform(handle);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to perform CURL operation: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	curl_result = curl_easy_getinfo(handle, CURLINFO_RESPONSE_CODE, &http_code);
	if (curl_result != CURLE_OK) {
		LogEvent(COMPONENT_CLIENTID, "Failed to perform CURL operation: %s", curl_easy_strerror(curl_result));
		goto error;
	}

	if (http_code != 200) {
		LogEvent(COMPONENT_CLIENTID, "HTTP error: %ld (url=%s, payload=%s)", http_code, url, payload);
		goto error;
	}

	*output = buffer.memory;
	*output_size = buffer.size;
	result = 0;
error:
	if (result != 0) {
		if (buffer.memory != NULL) {
			free(buffer.memory);
			buffer.memory = NULL;
			*output = NULL;
			*output_size = 0;
		}
	}
	if (curl_headers != NULL)
		curl_slist_free_all(curl_headers);
	if (encoded_url != NULL)
		free(encoded_url);
	if (handle != NULL)
		curl_easy_cleanup(handle);

	return result;
}

/**
 * @brief convert clientid opaque bytes as a hex string for mkdir purpose.
 *
 * @param[in,out] dspbuf The buffer.
 * @param[in]     value  The bytes to display
 * @param[in]     len    The number of bytes to display
 *
 * @return the bytes remaining in the buffer.
 *
 */
static int longhorn_convert_opaque_value_max_for_dir(struct display_buffer *dspbuf,
					       void *value,
					       int len,
					       int max)
{
	unsigned int i = 0;
	int          b_left = display_start(dspbuf);
	int          cpy = len;

	if (b_left <= 0)
		return 0;

	/* Check that the length is ok
	 * If the value is empty, display EMPTY value. */
	if (len <= 0 || len > max)
		return 0;

	/* If the value is NULL, display NULL value. */
	if (value == NULL)
		return 0;

	/* Determine if the value is entirely printable characters, */
	/* and it contains no slash character (reserved for filename) */
	for (i = 0; i < len; i++)
		if ((!isprint(((char *)value)[i])) ||
		    (((char *)value)[i] == '/'))
			break;

	if (i == len) {
		/* Entirely printable character, so we will just copy the
		 * characters into the buffer (to the extent there is room
		 * for them).
		 */
		b_left = display_len_cat(dspbuf, value, cpy);
	} else {
		b_left = display_opaque_bytes(dspbuf, value, cpy);
	}

	if (b_left <= 0)
		return 0;

	return b_left;
}

/**
 * @brief generate a name that identifies this client
 *
 * This name will be used to know that a client was talking to the
 * server before a restart so that it will be allowed to do reclaims
 * during grace period.
 *
 * @param[in] clientid Client record
 */
static void longhorn_create_clid_name(nfs_client_id_t *clientid)
{
	nfs_client_record_t *cl_rec = clientid->cid_client_record;
	const char *str_client_addr = "(unknown)";
	char cidstr[PATH_MAX] = { 0, };
	struct display_buffer dspbuf = {sizeof(cidstr), cidstr, cidstr};
	char cidstr_lenx[5];
	int total_size, cidstr_lenx_len, cidstr_len, str_client_addr_len;

	/* get the caller's IP addr */
	if (clientid->gsh_client != NULL)
		str_client_addr = clientid->gsh_client->hostaddr_str;

	if (longhorn_convert_opaque_value_max_for_dir(&dspbuf,
						cl_rec->cr_client_val,
						cl_rec->cr_client_val_len,
						PATH_MAX) > 0) {
		cidstr_len = strlen(cidstr);
		str_client_addr_len = strlen(str_client_addr);

		/* longhorn_convert_opaque_value_max_for_dir does not prefix
		 * the "(<length>:". So we need to do it here */
		cidstr_lenx_len = snprintf(cidstr_lenx, sizeof(cidstr_lenx),
					   "%d", cidstr_len);

		if (unlikely(cidstr_lenx_len >= sizeof(cidstr_lenx) ||
			     cidstr_lenx_len < 0)) {
			/* cidrstr can at most be PATH_MAX or 1024, so at most
			 * 4 characters plus NUL are necessary, so we won't
			 * overrun, nor can we get a -1 with EOVERFLOW or EINVAL
			 */
			LogFatal(COMPONENT_CLIENTID,
				 "snprintf returned unexpected %d",
				 cidstr_lenx_len);
		}

		total_size = cidstr_len + str_client_addr_len + 5 +
			     cidstr_lenx_len;

		/* hold both long form clientid and IP */
		clientid->cid_recov_tag = gsh_malloc(total_size);

		/* Can't overrun and shouldn't return EOVERFLOW or EINVAL */
		(void) snprintf(clientid->cid_recov_tag, total_size,
				"%s:%s",
				cidstr_lenx, cidstr);
	}

	LogDebug(COMPONENT_CLIENTID, "Created client name [%s]",
		 clientid->cid_recov_tag);
}

static int longhorn_recov_init(void)
{
	char host[NI_MAXHOST];
	char payload[PAYLOAD_MAX];
	char *response = NULL;
	size_t response_size = 0;
	char *version = NULL;
	int err = 0;
	int res = 0;

	err = gethostname(host, sizeof(host));
	if (err) {
		LogEvent(COMPONENT_CLIENTID,
				 "Failed to gethostname: %s (%d)",
				 strerror(errno), errno);
		return -errno;
	}

	LogEvent(COMPONENT_CLIENTID, "Initialize recovery backend '%s'", host);

	version = generate_random_string(VERSION_BYTES);
	assert(version != NULL);

	memcpy(recov_version, version, VERSION_BYTES + 1);

	snprintf(payload, sizeof(payload), "{\"hostname\": \"%s\", \"version\": \"%s\"}",
		host, recov_version);

	free(version);
	version = NULL;

	PTHREAD_RWLOCK_wrlock(&recov_lock);
	res = http_call(HTTP_POST, LONGHORN_RECOVERY_BACKEND_URL,
		payload, strlen(payload) + 1,
		&response, &response_size);
	PTHREAD_RWLOCK_unlock(&recov_lock);
	if (res != 0) {
		LogFatal(COMPONENT_CLIENTID, "HTTP call error: res=%d (%s)", res, response);
		return -EINVAL;
	}

	return 0;
}

static void longhorn_recov_end_grace(void)
{
	char host[NI_MAXHOST];
	char url[URL_MAX];
	char payload[PAYLOAD_MAX];
	char *response = NULL;
	size_t response_size = 0;
	int err = 0;
	int res = 0;

	err = gethostname(host, sizeof(host));
	if (err) {
		LogEvent(COMPONENT_CLIENTID,
				 "Failed to gethostname: %s (%d)",
				 strerror(errno), errno);
		return;
	}

	LogEvent(COMPONENT_CLIENTID,
			 "End grace for recovery backend '%s' version %s",
			 host, recov_version);

	snprintf(url, sizeof(url), "%s/%s", LONGHORN_RECOVERY_BACKEND_URL, host);
	snprintf(payload, sizeof(payload), "{\"version\": \"%s\"}", recov_version);

	PTHREAD_RWLOCK_wrlock(&recov_lock);
	res = http_call(HTTP_PUT, url, payload, strlen(payload) + 1, &response, &response_size);
	PTHREAD_RWLOCK_unlock(&recov_lock);
	if (res != 0) {
		LogFatal(COMPONENT_CLIENTID, "HTTP call error: res=%d (%s)", res, response);
	}
}

static void longhorn_add_clid(nfs_client_id_t *clientid)
{
	char host[NI_MAXHOST];
	char url[URL_MAX];
	char payload[PAYLOAD_MAX];
	char *response = NULL;
	size_t response_size = 0;
	CURL *curl = NULL;
	char *encoded_cid_recov_tag = NULL;
	int err = 0;
	int res = 0;

	err = gethostname(host, sizeof(host));
	if (err) {
		LogEvent(COMPONENT_CLIENTID,
				 "Failed to gethostname: %s (%d)",
				 strerror(errno), errno);
		return;
	}

	longhorn_create_clid_name(clientid);

	curl = curl_easy_init();
	assert(curl != NULL);

	encoded_cid_recov_tag = curl_easy_escape(curl,
		clientid->cid_recov_tag, strlen(clientid->cid_recov_tag));
	assert(encoded_cid_recov_tag != NULL);

	LogEvent(COMPONENT_CLIENTID,
			 "Add client '%s' to recovery backend %s",
			 clientid->cid_recov_tag, host);

	snprintf(url, sizeof(url), "%s/%s/%s",
		LONGHORN_RECOVERY_BACKEND_URL, host, encoded_cid_recov_tag);

	snprintf(payload, sizeof(payload), "{\"version\": \"%s\"}", recov_version);

	curl_free(encoded_cid_recov_tag);
	encoded_cid_recov_tag = NULL;

	PTHREAD_RWLOCK_wrlock(&recov_lock);
	res = http_call(HTTP_PUT, url, payload, strlen(payload) + 1, &response, &response_size);
	PTHREAD_RWLOCK_unlock(&recov_lock);
	if (res != 0) {
		LogFatal(COMPONENT_CLIENTID, "HTTP call error: res=%d (%s)", res, response);
	}

	curl_easy_cleanup(curl);
}

static void longhorn_rm_clid(nfs_client_id_t *clientid)
{
	char host[NI_MAXHOST];
	char url[URL_MAX];
	char *response = NULL;
	size_t response_size = 0;
	CURL *curl = NULL;
	char *encoded_cid_recov_tag = NULL;
	int err = 0;
	int res = 0;

	err = gethostname(host, sizeof(host));
	if (err) {
		LogEvent(COMPONENT_CLIENTID,
				 "Failed to gethostname: %s (%d)",
				 strerror(errno), errno);
		return;
	}

	curl = curl_easy_init();
	assert(curl != NULL);

	encoded_cid_recov_tag = curl_easy_escape(curl,
		clientid->cid_recov_tag, strlen(clientid->cid_recov_tag));
	assert(encoded_cid_recov_tag != NULL);

	clientid->cid_recov_tag = NULL;

	LogEvent(COMPONENT_CLIENTID,
			 "Remove client '%s' from recovery backend %s (%s)",
			 encoded_cid_recov_tag, host, encoded_cid_recov_tag);

	snprintf(url, sizeof(url), "%s/%s/%s",
		LONGHORN_RECOVERY_BACKEND_URL, host, encoded_cid_recov_tag);

	curl_free(encoded_cid_recov_tag);
	encoded_cid_recov_tag = NULL;

	PTHREAD_RWLOCK_wrlock(&recov_lock);
	res = http_call(HTTP_DELETE, url, NULL, 0, &response, &response_size);
	PTHREAD_RWLOCK_unlock(&recov_lock);
	if (res != 0) {
		LogFatal(COMPONENT_CLIENTID, "HTTP call error: res=%d (%s)", res, response);
	}

	curl_easy_cleanup(curl);
}

static int read_clids(char *response, add_clid_entry_hook add_clid_entry)
{
        struct json_object *obj = NULL, *clients_obj = NULL;
		size_t num_clids = 0;
		int error = -1;

		LogEvent(COMPONENT_CLIENTID, "response=%s", response);
		
		obj = json_tokener_parse(response);
		if (!obj) {
			LogEvent(COMPONENT_CLIENTID, "Failed to parse \"%s\": %s", response, strerror(errno));
			goto end;
		}

		clients_obj = json_object_object_get(obj, "clients");
		if (!clients_obj) {
			error = 0;
			LogEvent(COMPONENT_CLIENTID, "clients is empty");
			goto end;
		}

		num_clids = json_object_array_length(clients_obj);
		for (size_t i = 0; i < num_clids; i++) {
			struct json_object *obj = NULL;
			const char *clid = NULL;
			clid_entry_t *ent = NULL;

			obj = json_object_array_get_idx(clients_obj, i);
			if (!obj) {
				LogEvent(COMPONENT_CLIENTID, "Failed get client object: %s", strerror(errno));
				goto end;
			}

			clid = json_object_get_string(obj);
			ent = add_clid_entry((char *)clid);
			LogEvent(COMPONENT_CLIENTID, "Added %s to clid list", ent->cl_name);
		}

		error = 0;
end:
		json_object_put(obj);
		return error;
}

static void longhorn_read_recov_clids(nfs_grace_start_t *gsp,
				  add_clid_entry_hook add_clid_entry,
				  add_rfh_entry_hook add_rfh_entry)
{
	char host[NI_MAXHOST];
	char url[URL_MAX];
	char *response = NULL;
	size_t response_size = 0;
	int err = 0; 
	int res = 0;

	err = gethostname(host, sizeof(host));
	if (err) {
		LogEvent(COMPONENT_CLIENTID,
				 "Failed to gethostname: %s (%d)",
				 strerror(errno), errno);
		return;
	}

	LogEvent(COMPONENT_CLIENTID, "Read clients from recovery backend %s", host);

	snprintf(url, sizeof(url), "%s/%s", LONGHORN_RECOVERY_BACKEND_URL, host);

	PTHREAD_RWLOCK_rdlock(&recov_lock);
	res = http_call(HTTP_GET, url, NULL, 0, &response, &response_size);
	PTHREAD_RWLOCK_unlock(&recov_lock);
	if (res != 0) {
		LogFatal(COMPONENT_CLIENTID, "HTTP call error: res=%d (%s)", res, response);
		return;
	}

	read_clids(response, add_clid_entry);
}

static void longhorn_add_revoke_fh(nfs_client_id_t *delr_clid, nfs_fh4 *delr_handle)
{
	char host[NI_MAXHOST];
	char url[URL_MAX];
	char payload[PAYLOAD_MAX];
	char *response = NULL;
	size_t response_size = 0;
	char rhdlstr[NAME_MAX];
	int rhdlstr_len = 0;
	CURL *curl = NULL;
	char *encoded_cid_recov_tag = NULL;
	char *encoded_rhdlstr = NULL;
	int retval = 0;
	int res = 0;
	int err = 0;

	err = gethostname(host, sizeof(host));
	if (err) {
		LogEvent(COMPONENT_CLIENTID,
				 "Failed to gethostname: %s (%d)",
				 strerror(errno), errno);
		return;
	}

	/* Convert nfs_fh4_val into base64 encoded string */
	retval = base64url_encode(delr_handle->nfs_fh4_val,
							  delr_handle->nfs_fh4_len,
							  rhdlstr, sizeof(rhdlstr));
	assert(retval != -1);
	rhdlstr_len = strlen(rhdlstr);

	curl = curl_easy_init();
	assert(curl != NULL);

	encoded_cid_recov_tag = curl_easy_escape(curl,
		delr_clid->cid_recov_tag, strlen(delr_clid->cid_recov_tag));
	assert(encoded_cid_recov_tag != NULL);

	encoded_rhdlstr = curl_easy_escape(curl,
		rhdlstr, strlen(rhdlstr));
	assert(encoded_rhdlstr != NULL);

	snprintf(url, sizeof(url), "%s/%s/%s/%s/%s",
		LONGHORN_RECOVERY_BACKEND_URL, host, encoded_cid_recov_tag, encoded_rhdlstr);

	snprintf(payload, sizeof(payload), "{\"version\": \"%s\"}", recov_version);

	curl_free(encoded_cid_recov_tag);
	encoded_cid_recov_tag = NULL;

	curl_free(encoded_rhdlstr);
	encoded_rhdlstr = NULL;

	PTHREAD_RWLOCK_wrlock(&recov_lock);
	res = http_call(HTTP_PUT, url, payload, strlen(payload) + 1, &response, &response_size);
	PTHREAD_RWLOCK_unlock(&recov_lock);
	if (res != 0) {
		LogFatal(COMPONENT_CLIENTID, "HTTP call error: res=%d (%s)", res, response);
	}

	curl_easy_cleanup(curl);
}

static struct nfs4_recovery_backend longhorn_backend = {
	.recovery_init = longhorn_recov_init,
	.end_grace = longhorn_recov_end_grace,
	.recovery_read_clids = longhorn_read_recov_clids,
	.add_clid = longhorn_add_clid,
	.rm_clid = longhorn_rm_clid,
	.add_revoke_fh = longhorn_add_revoke_fh,
};

void longhorn_backend_init(struct nfs4_recovery_backend **backend)
{
	*backend = &longhorn_backend;
}
