/*
** Zabbix
** Copyright (C) 2014 Martin Dojcak
**
** Contact:
**              e-mail: martin@dojcak.sk
**              jabber: martindojcak@jabbim.sk
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/

/* EAI_CANCELED, EAI_NODATA */
#define _GNU_SOURCE

#include "checks_web.h"
#include "common.h"
#include "comms.h"
#include "log.h"
#include "zbxregexp.h"
#include "dbcache.h"

#ifdef HAVE_LIBCURL
#include <curl/curl.h>
#include <netdb.h>

extern int     CONFIG_POLLER_WEB_TIMEOUT;

static struct web_curl_time_set WEB_CURL_TIME[] = {
        {"connect", CURLINFO_CONNECT_TIME},
        {"appconnect", CURLINFO_APPCONNECT_TIME},
        {"pretrans", CURLINFO_PRETRANSFER_TIME},
        {"starttrans", CURLINFO_STARTTRANSFER_TIME},
        {"total", CURLINFO_TOTAL_TIME},
        {"redir", CURLINFO_REDIRECT_TIME},
        {NULL, 0}
};

static  struct web_id_set WEB_ID_OPT[] = {
	/* ID 0 CHECK */
	{WEB_CHECK_ID, WEB_CHECK_KEY, WEB_CHECK_PARAM_MIN, WEB_CHECK_PARAM_MAX},
	/* ID 1 CHECK_BAUTH */
	{WEB_CHECK_BAUTH_ID, WEB_CHECK_BAUTH_KEY, WEB_CHECK_BAUTH_PARAM_MIN, WEB_CHECK_BAUTH_PARAM_MAX},
	/* ID 2 CHECK_HEADER */
	{WEB_CHECK_HEADER_ID, WEB_CHECK_HEADER_KEY, WEB_CHECK_HEADER_PARAM_MIN, WEB_CHECK_HEADER_PARAM_MAX},
	/* ID 3 CHECK_IMG */
	{WEB_CHECK_IMG_ID, WEB_CHECK_IMG_KEY, WEB_CHECK_IMG_PARAM_MIN, WEB_CHECK_IMG_PARAM_MAX},
	/* ID 4 CHECK_TIME */
	{WEB_CHECK_TIME_ID, WEB_CHECK_TIME_KEY, WEB_CHECK_TIME_PARAM_MIN, WEB_CHECK_TIME_PARAM_MAX},
	/* END  */
	{0, NULL, 0 ,0}
};

static struct web_param_set WEB_PARAM_OPT[][WEB_PARAM_OPT_COUNT] = {
	/* ID 0 CHECK */
	{{1, web_set_required_response}, {2, web_set_ip}, {3, web_set_port}, {4, web_set_host}, {5, web_set_uri},
	 {6, web_set_timeout}, {7, web_set_regexp}, {8, web_set_regexp}, {9, web_set_regexp}, {10, web_set_regexp},
	 {11, web_set_regexp}},
	/* ID 1 CHECK_BAUTH */
	{{1, web_set_required_response}, {2, web_set_ip}, {3, web_set_port}, {4, web_set_host}, {5, web_set_uri},
	 {6, web_set_timeout}, {7, web_set_login}, {8, web_set_regexp}, {9, web_set_regexp}, {10, web_set_regexp},
	 {11, web_set_regexp}, {12,web_set_regexp}},
	/* ID 2 CHECK_HEADER */
	{{1, web_set_required_response}, {2, web_set_ip}, {3, web_set_port}, {4, web_set_host}, {5, web_set_uri},
	 {6, web_set_timeout}, {7, web_set_regexp}, {8, web_set_regexp}, {9, web_set_regexp}, {10, web_set_regexp},
	 {11, web_set_regexp}},
	/* ID 3 CHECK_IMG */
	{{1, web_set_ip},{2, web_set_port}, {3, web_set_host}, {4, web_set_uri}, {5, web_set_timeout}},
	/* ID 4 CHECK_TIME */
	{{1, web_set_ip}, {2, web_set_port}, {3, web_set_host}, {4, web_set_uri}, {5, web_set_timeout},
	 {6, web_set_time_expression}},
	/* END  */
	{{6, NULL}}
};

static struct web_curl_set WEB_CURL_OPT[][WEB_CURL_OPT_COUNT] = {
	/* ID 0 CHECK */
	{{web_curl_set_body_write}, {web_curl_set_header_write_throw}},
	/* ID 1 CHECK_BAUTH */
	{{web_curl_set_bauth}, {web_curl_set_body_write}, {web_curl_set_header_write_throw}},
	/* ID 2 CHECK_HEADER */
	{{web_curl_set_body_write_throw},{ web_curl_set_header_write}},
	/* ID 3 CHECK_IMG */
	{{web_curl_set_body_write_throw}, {web_curl_set_header_write_throw}},
	/* ID 4 CHECK_TIME */
	{{web_curl_set_body_write_throw}, {web_curl_set_header_write_throw}},
	/* END  */
	{{NULL}}
};

static struct web_key_check_set WEB_KEY_CHECK_OPT[][WEB_KEY_CHECK_COUNT] = {
	/* ID 0 CHECK */
	{{web_key_check_regexp}},
	/* ID 1 CHECK_BAUTH */
	{{web_key_check_regexp}},
	/* ID 2 CHECK_HEADER */
	{{web_key_check_regexp}},
	/* ID 3 CHECK_IMG */
	{{web_key_check_img}},
	/* ID 4 CHECK_TIME */
	{{web_key_check_time}},
	/* END  */
	{{NULL}}
};

void web_free(struct web *p)
{
	int i;

	zbx_free(p->ip);
	zbx_free(p->port);
	zbx_free(p->host);
	zbx_free(p->uri);
	zbx_free(p->username);
	zbx_free(p->passwd);

	if (p->regexp)
		for (i = 0; i < p->regexp_count; i++)
			zbx_free(p->regexp[i]);
	zbx_free(p->regexp);

        if (p->header)
                for (i = 0; i < p->header_count; i++)
                        zbx_free(p->header[i]);
        zbx_free(p->header);

	zbx_free(p->username);
	zbx_free(p->passwd);

	if (p->curl) {
		if (p->curl->handler)
			curl_easy_cleanup(p->curl->handler);

		if (p->curl->header_lst)
			curl_slist_free_all(p->curl->header_lst);

		if (p->curl->body)
			zbx_free(p->curl->body->buff);
		zbx_free(p->curl->body);

		if (p->curl->header)
			zbx_free(p->curl->header->buff);
		zbx_free(p->curl->header);

		zbx_free(p->curl);
	}

	zbx_free(p);
}

static int web_set_key(DC_ITEM *item, struct web *opt, const char *cmd)
{
	int i;

	for (i = 0; WEB_ID_OPT[i].key_name != NULL; i++) {
		if (!strncmp(WEB_ID_OPT[i].key_name, cmd, strlen(cmd))) {
			opt->key_id = WEB_ID_OPT[i].key_id;
			opt->item = item;
			return SUCCEED;
		}
	}

	return FAIL;
}

static int web_set_params_count(AGENT_RESULT *result, struct web *opt, const char *params)
{
	opt->params_count = num_param(params);
        opt->params_min = WEB_ID_OPT[opt->key_id].params_min;
        opt->params_max = WEB_ID_OPT[opt->key_id].params_max;

        if (opt->params_count > opt->params_max || opt->params_count < opt->params_min) {
                SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid  number of parameters", NULL));
                return FAIL;
        }

	return SUCCEED;
}

static int web_set_required_response(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char req_code_tmp[WEB_MAX_HTTP_CODE_STRLEN] = {0};
	zbx_uint64_t req_code_test;

	if (get_param(params, param_id, req_code_tmp, WEB_MAX_HTTP_CODE_STRLEN))
		goto failed;

	if (strlen(req_code_tmp))
	{
		if (is_uint_range(req_code_tmp, &req_code_test, WEB_MIN_HTTP_CODE, WEB_MAX_HTTP_CODE))
			goto failed;

		opt->required_response = (int) req_code_test;
		return SUCCEED;
	} else {
		opt->required_response = WEB_DEF_HTTP_CODE;
		return SUCCEED;
	}

failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid RESPONSE CODE parameter", NULL));
	return FAIL;
}

static int web_resolv_dns(struct web *opt, const char *dns)
{
	const char *__function_name = "web_resolv_dns";

	struct addrinfo hints, *p, *res;
	struct sockaddr_in *ipv4;
#if defined(HAVE_IPV6)
	struct sockaddr_in6 *ipv6;
#endif  /*HAVE_IPV6*/
	void *addr = NULL;
	int state;
	char ip_tmp[INET6_ADDRSTRLEN] = {0};

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = 0;
	hints.ai_protocol = 0;

	if ((state = getaddrinfo(dns, NULL, &hints, &res)))
		goto failed;

	for (p = res; p != NULL; p = p->ai_next) {
		if (p->ai_family == AF_INET) {
			opt->is_ipv6 = (zbx_uint64_t) 0;
			ipv4 = (struct sockaddr_in *)p->ai_addr;
			addr = &(ipv4->sin_addr);
		}
#if defined(HAVE_IPV6)
		else {
			opt->is_ipv6 = (zbx_uint64_t) 1;
			ipv6 = (struct sockaddr_in6 *)p->ai_addr;
			addr = &(ipv6->sin6_addr);
		}
#endif  /*HAVE_IPV6*/

		inet_ntop(p->ai_family, addr, ip_tmp, sizeof ip_tmp);
		if (*ip_tmp) {
			freeaddrinfo(res);
			opt->ip =  zbx_strdup(NULL,ip_tmp);
			return SUCCEED;
		}
	}
failed:
	zabbix_log(LOG_LEVEL_WARNING, "%s(): %s for dns %s in key %s",
		   __function_name, gai_strerror(state), dns, opt->item->key);

	if( state == EAI_AGAIN || state == EAI_NONAME || state == EAI_CANCELED || state == EAI_NODATA ) {
		opt->result = (zbx_uint64_t) WEB_ERR_DNS;
		return SUCCEED;
	}

	return FAIL;
}

static int web_set_ip(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char ip_tmp[WEB_MAX_DNS_STRLEN] = {0};

	/* RFC1035 */
        if (get_param(params, param_id, ip_tmp, WEB_MAX_DNS_STRLEN))
                goto failed;

	zbx_remove_whitespace(ip_tmp);

	if (strlen(ip_tmp)) {
		if (!is_ip4(ip_tmp)) {
			opt->is_ipv6 = (zbx_uint64_t) 0;
			opt->ip =  zbx_strdup(NULL, ip_tmp);
			return SUCCEED;
		}
#if defined(HAVE_IPV6)
		else if (!is_ip6(ip_tmp)) {
			opt->is_ipv6 = (zbx_uint64_t) 1;
			opt->ip = zbx_strdup(NULL, ip_tmp);
			return SUCCEED;
		}
#endif  /*HAVE_IPV6*/
		else if (!(zbx_check_hostname(ip_tmp))) {
			opt->host = zbx_strdup(NULL, ip_tmp);
			 return web_resolv_dns(opt, opt->host);
		} else {
			goto failed;
		}
	} else {
		if (opt->item->interface.useip) {
			opt->ip = zbx_strdup(NULL, opt->item->interface.ip_orig);
			return SUCCEED;
		} else {
			opt->host = zbx_strdup(NULL, opt->item->interface.dns_orig);
			return web_resolv_dns(opt, opt->item->interface.dns_orig);
		}
	}

failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid IP / DNS parameter", NULL));
	return FAIL;
}

static int web_set_port(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char port_tmp[WEB_MAX_PORT_STRLEN] = {0};

	if (get_param(params, param_id, port_tmp, WEB_MAX_PORT_STRLEN))
		goto failed;

	zbx_remove_whitespace(port_tmp);

	if (strlen(port_tmp)) {
		/* RFC6335 */
		if (is_uint_range(port_tmp, NULL, 0, WEB_MAX_PORT))
			goto failed;

		if (strncmp(port_tmp, "443", strlen(port_tmp)))
			opt->is_https = (zbx_uint64_t) 0;
		else
			opt->is_https = (zbx_uint64_t) 1;

		opt->port = zbx_strdup(NULL, port_tmp);
	} else {
		opt->port = zbx_strdup(NULL, WEB_DEF_PORT);
	}

	return SUCCEED;
failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid PORT parameter", NULL));
	return FAIL;
}

static int web_set_host(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char host_tmp[WEB_MAX_DNS_STRLEN] = {0};

	if (get_param(params, param_id, host_tmp, WEB_MAX_DNS_STRLEN))
		goto failed;

	zbx_remove_whitespace(host_tmp);

	if (strlen(host_tmp)) {
		if (!strncmp(host_tmp, "none", strlen(host_tmp))) {
			if (opt->host)
                                zbx_free(opt->host);
		} else {
			/* RFC2616 14.23 non compliant. We dont accept port number in Host field */
			if (zbx_check_hostname(host_tmp))
				goto failed;
			/* if hostname is previously set in IP / DNS then replace it with user param */
			if (opt->host)
				zbx_free(opt->host);

			opt->host = zbx_strdup(NULL, host_tmp);
		}
	}

	return SUCCEED;
failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid HOST parameter", NULL));
	return FAIL;
}

static int web_set_uri(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char req_uri_tmp[MAX_STRING_LEN] = {0};

	if (get_param(params, param_id, req_uri_tmp, MAX_STRING_LEN)) {
		SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid URI parameter", NULL));
		return FAIL;
	}

	zbx_remove_whitespace(req_uri_tmp);

	if (strlen(req_uri_tmp))
		opt->uri = zbx_strdup(NULL, req_uri_tmp);
	else
		opt->uri = zbx_strdup(NULL, WEB_DEF_URI);

	return SUCCEED;
}

static int web_set_timeout(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char timeout_tmp[WEB_MAX_TIMEOUT_STRLEN] = {0};
	zbx_uint64_t timeout_test;

	/* maximum is one digit timeout */
	if (get_param(params, param_id, timeout_tmp, WEB_MAX_TIMEOUT_STRLEN))
		goto failed;

	zbx_remove_whitespace(timeout_tmp);

	if (strlen(timeout_tmp)) {
		/* check timeout range 1 to WEB_MAX_TIMEOUT */
		/* and convert string to uint64 */
		if (is_uint_range(timeout_tmp, &timeout_test, 1, WEB_MAX_TIMEOUT))
			goto failed;

		opt->timeout = timeout_test;
		return SUCCEED;
	} else {
		opt->timeout = WEB_DEF_TIMEOUT;
		return SUCCEED;
	}

failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid TIMEOUT parameter", NULL));
	return FAIL;
}

static int web_set_regexp(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char regexp_tmp[WEB_MAX_REGEXP_STRLEN] = {0};


	if (get_param(params, param_id, regexp_tmp, WEB_MAX_REGEXP_STRLEN)) {
		SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid REGEXP parameter", NULL));
		return FAIL;
	}

	if (strlen(regexp_tmp)) {
		opt->regexp = (char **) zbx_realloc(opt->regexp, (opt->regexp_count + 1) * sizeof(char **));
		opt->regexp[opt->regexp_count] = zbx_strdup(NULL, regexp_tmp);
		opt->regexp_count++;
	}

	return SUCCEED;
}

static int web_set_login(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char login_tmp[MAX_STRING_LEN] = {0};
	char *passwd_ptr = NULL;
	size_t user_lenght;

	if (get_param(params, param_id, login_tmp, MAX_STRING_LEN))
		goto failed;

	zbx_remove_whitespace(login_tmp);

	if (!(passwd_ptr = strchr(login_tmp, ':')))
		goto failed;

	if (!(user_lenght = strlen(login_tmp) - strlen(passwd_ptr)))
		goto failed;

	opt->username = strndup(login_tmp, user_lenght);
	opt->passwd = zbx_strdup(opt->passwd, ++passwd_ptr);

	return SUCCEED;
failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid LOGIN parameter", NULL));
	return FAIL;
}

static int web_set_time_expression(AGENT_RESULT *result, struct web *opt, const char *params, int param_id)
{
	char time_tmp[WEB_MAX_TIME_STRLEN] = {0};
	int i;

	if (get_param(params, param_id, time_tmp, WEB_MAX_TIME_STRLEN))
		goto failed;

	zbx_remove_whitespace(time_tmp);

        for (i = 0; WEB_CURL_TIME[i].time_name != NULL; i++) {
                if (!strncmp(WEB_CURL_TIME[i].time_name, time_tmp, strlen(time_tmp))) {
                        opt->curl_time_flag = WEB_CURL_TIME[i].curl_time_flag;
                        return SUCCEED;
                }
        }

failed:
	SET_MSG_RESULT(result, zbx_dsprintf(NULL, "Invalid TIME parameter", NULL));
        return FAIL;
}

static int web_curl_set_common(struct web *opt)
{
	const char *__function_name = "web_curl_set_common";

	char *curl_err_str = NULL;
	int curl_err;
	int curl_opt;

	if (!(opt->curl->handler = curl_easy_init())) {
		zabbix_log(LOG_LEVEL_ERR,"%s(): Could not init cURL for key %s", __function_name, opt->item->key);
		goto failed;
	}

	if ((curl_err = curl_easy_setopt(opt->curl->handler, curl_opt = CURLOPT_COOKIEFILE, "")) ||
	    (curl_err = curl_easy_setopt(opt->curl->handler, curl_opt = CURLOPT_SSL_VERIFYPEER, 0L)) ||
	    (curl_err = curl_easy_setopt(opt->curl->handler, curl_opt = CURLOPT_SSL_VERIFYHOST, 0L)) ||
	    (curl_err = curl_easy_setopt(opt->curl->handler, curl_opt = CURLOPT_USERAGENT,WEB_CURL_USERAGENT)) ||
	    (curl_err = curl_easy_setopt(opt->curl->handler, curl_opt = CURLOPT_TIMEOUT, (long) opt->timeout))) {
                curl_err_str = zbx_strdup(curl_err_str,curl_easy_strerror(curl_err));
                zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, curl_opt, curl_err_str, opt->item->key);
                goto failed;
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_curl_set_url(struct web *opt)
{
	const char *__function_name = "web_curl_set_url";

	char *url = NULL;
	char *curl_err_str = NULL;
	int curl_err;
	size_t alloc;
	size_t offset;

	if (opt->is_https)
		url = zbx_strdup(url, "https://");
	else
		url = zbx_strdup(url, "http://");

	offset = strlen(url);
	alloc = sizeof(char) * offset + 1;

	if (opt->is_ipv6) {
		zbx_strncpy_alloc(&url, &alloc, &offset, "[", 1);
		zbx_strncpy_alloc(&url, &alloc, &offset, opt->ip, strlen(opt->ip));
		zbx_strncpy_alloc(&url, &alloc, &offset, "]", 1);
	} else {
		zbx_strncpy_alloc(&url, &alloc, &offset, opt->ip, strlen(opt->ip));
	}

	zbx_strncpy_alloc(&url, &alloc, &offset, ":", 1);
	zbx_strncpy_alloc(&url, &alloc, &offset, opt->port, strlen(opt->port));

	if (*opt->uri != '/')
		zbx_strncpy_alloc(&url, &alloc, &offset, "/", 1);

	zbx_strncpy_alloc(&url, &alloc, &offset, opt->uri, strlen(opt->uri));

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_URL, url))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_URL, curl_err_str, opt->item->key);
		zbx_free(curl_err_str);
		zbx_free(url);
		return FAIL;
        }

	zbx_free(url);
	return SUCCEED;
}

static int web_curl_set_header(struct web *opt)
{
	const char *__function_name = "web_curl_set_header";

	char *host = NULL;
	char *curl_err_str = NULL;
	int curl_err;
	int i;
	size_t offset;
	size_t alloc;

	if (opt->host) {
		host = zbx_strdup(host, "Host: ");
		offset = strlen(host);
		alloc = sizeof(char) * offset + 1;

		zbx_strncpy_alloc(&host, &alloc, &offset, opt->host, strlen(opt->host));

		if (!(opt->curl->header_lst = curl_slist_append(opt->curl->header_lst, host))) {
				zabbix_log(LOG_LEVEL_ERR, "%s(): Could not append to curl header list for key %s",
							  __function_name, opt->item->key);
				goto failed;
		}
	}

	for (i = 0; i < opt->header_count; i++) {
		if (!(opt->curl->header_lst = curl_slist_append(opt->curl->header_lst, opt->header[i]))) {
			zabbix_log(LOG_LEVEL_ERR, "%s(): Could not append to curl header list for key %s",
						  __function_name, opt->item->key);
			goto failed;
		}
	}


	if (opt->curl->header_lst) {
		if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_HTTPHEADER, opt->curl->header_lst))) {
			curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
			zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
						  __function_name, CURLOPT_HTTPHEADER, curl_err_str, opt->item->key);
			goto failed;
		}
	}

	zbx_free(host);
	return SUCCEED;
failed:
	zbx_free(host);
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_curl_set_bauth(struct web *opt)
{
	const char *__function_name = "web_curl_set_bauth";

	char *curl_err_str = NULL;
	int curl_err;

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_USERNAME, opt->username))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_USERNAME, curl_err_str, opt->item->key);
		goto failed;
	}

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_PASSWORD, opt->passwd))) {
                curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
                zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_PASSWORD, curl_err_str, opt->item->key);
                goto failed;
        }

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_HTTPAUTH, CURLAUTH_BASIC))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_HTTPAUTH, curl_err_str, opt->item->key);
		goto failed;
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static size_t web_curl_write(void *contents, size_t size, size_t nmemb, void *userp)
{
	struct web_storage *page = (struct web_storage *)userp;
	size_t read_size = size * nmemb;

	if (!page->buff) {
		page->alloc = MAX(8096, read_size);
		page->offset = 0;
		page->buff = zbx_calloc(page->buff, 1, page->alloc);
	}

	zbx_strncpy_alloc(&page->buff, &page->alloc, &page->offset, contents, read_size);

	return read_size;
}

static size_t web_curl_write_throw(void *contents, size_t size, size_t nmemb, void *userp)
{
	return size * nmemb;
}

static int web_curl_set_body_write(struct web *opt)
{
	static char *__function_name = "web_curl_set_body_write";

	char *curl_err_str = NULL;
	int curl_err;

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_WRITEFUNCTION, web_curl_write))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_WRITEFUNCTION, curl_err_str, opt->item->key);
		goto failed;
	}

	opt->curl->body = (struct web_storage *) zbx_calloc(opt->curl->body, 1, sizeof(struct web_storage));

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_WRITEDATA, opt->curl->body))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_WRITEDATA, curl_err_str, opt->item->key);
		goto failed;
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_curl_set_body_write_throw(struct web *opt)
{
	static char *__function_name = "web_curl_set_body_write_throw";

	char *curl_err_str = NULL;
	int curl_err;

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_WRITEFUNCTION, web_curl_write_throw))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_WRITEFUNCTION, curl_err_str, opt->item->key);
		goto failed;
	}

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_WRITEDATA, NULL))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_WRITEDATA, curl_err_str, opt->item->key);
		goto failed;
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_curl_set_header_write(struct web *opt)
{
	static char *__function_name = "web_curl_set_header_write";

	char *curl_err_str = NULL;
	int curl_err;

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_HEADERFUNCTION, web_curl_write))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_HEADERFUNCTION, curl_err_str, opt->item->key);
		goto failed;
	}

	opt->curl->header = (struct web_storage *) zbx_calloc(opt->curl->header, 1, sizeof(struct web_storage));

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_WRITEHEADER, opt->curl->header))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_WRITEHEADER, curl_err_str, opt->item->key);
		goto failed;
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_curl_set_header_write_throw(struct web *opt)
{
	static char *__function_name = "web_curl_set_header_write_throw";

	char *curl_err_str = NULL;
	int curl_err;

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_HEADERFUNCTION, web_curl_write_throw))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_HEADERFUNCTION, curl_err_str, opt->item->key);
		goto failed;
	}

	if ((curl_err = curl_easy_setopt(opt->curl->handler, CURLOPT_WRITEHEADER, NULL))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Could not set cURL option [%d]: %s for key %s",
					  __function_name, CURLOPT_WRITEHEADER, curl_err_str, opt->item->key);
		goto failed;
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_curl_set(struct web *opt)
{
	int i;

	opt->curl = (struct web_curl *) zbx_calloc(opt->curl, 1, sizeof(struct web_curl));

	if (web_curl_set_common(opt))
		goto failed;

	if (web_curl_set_url(opt))
		goto failed;

	if (web_curl_set_header(opt))
		goto failed;

	/* set key specific curl settings*/
        for (i = 0; i < WEB_CURL_OPT_COUNT; i++) {
                if (WEB_CURL_OPT[opt->key_id][i].curl_set != NULL)
                        if (WEB_CURL_OPT[opt->key_id][i].curl_set(opt))
                                goto failed;
        }

	return SUCCEED;
failed:
	opt->result = (zbx_uint64_t) WEB_ERR_CURL;
	return FAIL;
}

static int web_curl_perform(struct web *opt)
{
	const char *__function_name = "web_curl_perform";

	char *curl_err_str = NULL;
	int  curl_err;
	long http_resp;

	if ((curl_err = curl_easy_perform(opt->curl->handler))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Error during curl_easy_perform: %s for key %s",
					  __function_name, curl_err_str, opt->item->key);
		opt->result = (zbx_uint64_t) curl_err;
		goto failed;
	}

	if ((curl_err = curl_easy_getinfo(opt->curl->handler, CURLINFO_RESPONSE_CODE, &http_resp))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Error during curl_easy_getinfo: %s for key %s",
					  __function_name, curl_err_str, opt->item->key);
		opt->result = (zbx_uint64_t) WEB_ERR_CURL;
		goto failed;
	}

	opt->result = (zbx_uint64_t) http_resp;
	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_match_regexp(struct web *opt, const char *content, const char *regexp)
{
	const char *__function_name = "web_match_regexp";

	if (content && regexp) {
                if (zbx_regexp_match(content, regexp, NULL))
                        return SUCCEED;
                else
                        zabbix_log(LOG_LEVEL_WARNING, "%s(): Required regexp not found %s for key %s",
						      __function_name, regexp, opt->item->key);
        }

	return FAIL;
}

static int web_key_check_regexp(struct web *opt)
{
	const char *__function_name = "web_key_check_regexp";

	char *content = NULL;
	int i;

	if (opt->required_response == (int) opt->result) {
		if (opt->curl->body) {
			if (opt->curl->body->buff)
				content = opt->curl->body->buff;
			else
				return SUCCEED;
		} else if (opt->curl->header) {
			if (opt->curl->header->buff)
				content = opt->curl->header->buff;
			else
				return SUCCEED;
		} else {
			/* this should never happend */
			goto failed;
		}

		for (i = 0; i < opt->regexp_count; i++) {
			if (web_match_regexp(opt, content, opt->regexp[i]))
				goto failed;
		}
	} else {
		zabbix_log(LOG_LEVEL_WARNING, 
			   "%s(): Required response code (%d) does not match (%"PRIu64") for key %s", 
			   __function_name, opt->required_response, opt->result, opt->item->key);
	}

	return SUCCEED;
failed:
	opt->result = (zbx_uint64_t) WEB_ERR_REGEXP;
	return FAIL;
}

static int web_key_check_img(struct web *opt)
{
	const char *__function_name = "web_key_check_img";

	char *content_type = NULL;
	char *curl_err_str = NULL;
	int curl_err;

	if (opt->required_response == WEB_CHECK_IMG_DEF_RESP) {

		if ((curl_err = curl_easy_getinfo(opt->curl->handler, CURLINFO_CONTENT_TYPE, &content_type))) {
			curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
			zabbix_log(LOG_LEVEL_ERR, "%s(): Error during curl_easy_getinfo: %s for key %s",
						  __function_name, curl_err_str, opt->item->key);
			opt->result = (zbx_uint64_t) WEB_ERR_CURL;
			goto failed;
		}

		if (!zbx_strcasestr(content_type, WEB_CHECK_IMG_MATCH_CTYPE)) {
			zabbix_log(LOG_LEVEL_WARNING, "%s(): Required content type %s not found for key %s",
						      __function_name, WEB_CHECK_IMG_MATCH_CTYPE, opt->item->key);
			opt->result = (zbx_uint64_t) WEB_ERR_CONTENT_TYPE;
			goto failed;
		}
	}

	return SUCCEED;
failed:
	zbx_free(curl_err_str);
	return FAIL;
}

static int web_key_check_time(struct web *opt)
{
	const char *__function_name = "web_key_check_time";

	char *curl_err_str = NULL;
	int curl_err;
	double curl_time;

	if ((curl_err = curl_easy_getinfo(opt->curl->handler, opt->curl_time_flag, &curl_time))) {
		curl_err_str = zbx_strdup(curl_err_str, curl_easy_strerror(curl_err));
		zabbix_log(LOG_LEVEL_ERR, "%s(): Error during curl_easy_getinfo: %s for key %s",
					  __function_name, curl_err_str, opt->item->key);
		opt->result = (zbx_uint64_t) WEB_ERR_CURL;
		zbx_free(curl_err_str);
		return FAIL;
	}

	/* convert second to milisecond */
	curl_time = curl_time * 1000;
	opt->result = (zbx_uint64_t) curl_time;
	return SUCCEED;
}

static int web_perform(DC_ITEM *item, AGENT_RESULT *result, const char *cmd, const char *params)
{
	struct web *opt = NULL;
	int i;

	opt = (struct web *) zbx_calloc(opt, 1, sizeof (struct web));

	if (web_set_key(item, opt, cmd))
		goto failed;

	if (web_set_params_count(result, opt, params))
		goto failed;

	/* web set & validate params */
	for (i = 0; i < opt->params_count; i++) {
		/* result can be set previously by web_set_ip (WEB_ERR_DNS) */
		if (opt->result)
			goto result;

		if (WEB_PARAM_OPT[opt->key_id][i].param_set != NULL)
			if (WEB_PARAM_OPT[opt->key_id][i].param_set(result, opt, params,
								    WEB_PARAM_OPT[opt->key_id][i].param_id))
				goto failed;
	}

	/* web set curl internal struct (WEB_ERR_CURL)*/
	if (web_curl_set(opt))
		goto result;

	/* web perform curl request (WEB_ERR_CURL)*/
	if (web_curl_perform(opt))
		goto result;

	/* web perform key specific check (WEB_ERR[CURL|CONTENT_TYPE|REGEXP])*/
	for (i = 0; i < WEB_KEY_CHECK_COUNT; i++) {
		if (WEB_KEY_CHECK_OPT[opt->key_id][i].key_check != NULL)
			if (WEB_KEY_CHECK_OPT[opt->key_id][i].key_check(opt))
				goto result;
	}

result:
	SET_UI64_RESULT(result, opt->result);
	web_free(opt);
	return SUCCEED;
failed:
	web_free(opt);
	return NOTSUPPORTED;
}

int get_value_web(DC_ITEM *item, AGENT_RESULT *result)
{
	const char *__function_name = "get_value_web";

	char cmd[MAX_STRING_LEN];
	char params[MAX_STRING_LEN];

	if (!parse_command(item->key, cmd, sizeof(cmd), params, sizeof(params))) {
                zabbix_log(LOG_LEVEL_ERR, "%s(): Parse key and values failed in key %s", __function_name, item->key);
                return FAIL;
        }

	return web_perform(item, result, cmd, params);
}

#endif /* HAVE_LIBCURL */
