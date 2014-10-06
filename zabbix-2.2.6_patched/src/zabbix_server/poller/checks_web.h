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

#ifndef ZABBIX_CHECKS_WEB_H
#define ZABBIX_CHECKS_WEB_H

#include "dbcache.h"
#include "module.h"
#include "common.h"


#ifdef HAVE_LIBCURL
#include <curl/curl.h>

#define CURL_SL struct curl_slist

/* web opt */
#define WEB_MAX_HTTP_CODE_STRLEN	(3 + 1)
#define WEB_MIN_HTTP_CODE		100
#define WEB_MAX_HTTP_CODE		599
#define WEB_DEF_HTTP_CODE		200

#define WEB_MAX_DNS_STRLEN      	(253 + 1)

#define WEB_MAX_PORT_STRLEN     	(5 + 1)
#define WEB_MAX_PORT            	65535
#define WEB_DEF_PORT            	"80"

#define WEB_DEF_URI             	"/"

#define WEB_MAX_TIMEOUT_STRLEN  	(2 + 1)
#define WEB_MAX_TIMEOUT         	(CONFIG_POLLER_WEB_TIMEOUT - 1)
#define WEB_DEF_TIMEOUT         	5

#define WEB_MAX_REGEXP_STRLEN   	(256 + 1)

#define WEB_MAX_TIME_STRLEN		(12 + 1)

#define WEB_CURL_USERAGENT      	"curl/zabbix"
#define WEB_CHECK_IMG_MATCH_CTYPE       "image"

/* key params opt*/
#define WEB_PARAM_OPT_COUNT		12

#define WEB_CHECK_KEY           	"web.check"
#define WEB_CHECK_PARAM_MIN     	6
#define WEB_CHECK_PARAM_MAX     	11

#define WEB_CHECK_BAUTH_KEY     	"web.check.bauth"
#define WEB_CHECK_BAUTH_PARAM_MIN	7
#define WEB_CHECK_BAUTH_PARAM_MAX	12

#define WEB_CHECK_HEADER_KEY    	"web.check.header"
#define WEB_CHECK_HEADER_PARAM_MIN     6
#define WEB_CHECK_HEADER_PARAM_MAX     11

#define WEB_CHECK_IMG_KEY       	"web.check.img"
#define WEB_CHECK_IMG_PARAM_MIN		5
#define WEB_CHECK_IMG_PARAM_MAX		5
#define WEB_CHECK_IMG_DEF_RESP		200

#define WEB_CHECK_TIME_KEY		"web.check.time"
#define WEB_CHECK_TIME_PARAM_MIN	6
#define WEB_CHECK_TIME_PARAM_MAX	6

/* key curl opt */
#define WEB_CURL_OPT_COUNT	3

/* key check */
#define WEB_KEY_CHECK_COUNT	1

enum {
        /* 0 - 99 reserved for cURL internal error */
        /* 100 - 599 reserved for http response */
        WEB_ERR_DNS = 600,
        WEB_ERR_CURL,
        WEB_ERR_REGEXP,
        WEB_ERR_CONTENT_TYPE,
        WEB_ERR_LAST            /* 604 */
};

enum {
        WEB_CHECK_ID = 0,       /* 0 */
        WEB_CHECK_BAUTH_ID,     /* 1 */
        WEB_CHECK_HEADER_ID,    /* 2 */
        WEB_CHECK_IMG_ID,       /* 3 */
        WEB_CHECK_TIME_ID       /* 4 */
};


struct web_curl_time_set {
	char 	*time_name;
	int	curl_time_flag;
};

struct web_storage {
	char	*buff;
	size_t	alloc;
	size_t	offset;
};

struct web_curl {
	CURL			*handler;
	struct curl_slist	*header_lst;
	struct web_storage	*body;
	struct web_storage	*header;
};

struct web {
	int		key_id;
	int             params_count;
	int		params_min;
	int		params_max;
	int		required_response;
	char		*ip;
	int		is_ipv6;
	char		*port;
	int		is_https;
	char		*host;
	char		*uri;
	int		timeout;
	char		**regexp;
	int		regexp_count;
	char		**header;
	int		header_count;
        int		 curl_time_flag;
        char		*username;
        char		*passwd;
	DC_ITEM		*item;
	struct web_curl	*curl;
	zbx_uint64_t	result;
};

struct web_id_set {
	int	key_id;
	char	*key_name;
	int	params_min;
	int	params_max;
};

struct web_param_set {
	int	param_id;
	int	(*param_set)(AGENT_RESULT *, struct web *, const char *, int);
};

struct web_curl_set {
	int (*curl_set)(struct web *);
};

struct web_key_check_set {
	int (*key_check)(struct web *);
};

int     get_value_web(DC_ITEM *item, AGENT_RESULT *result);

static int web_set_required_response(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_ip(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_port(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_host(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_uri(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_timeout(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);

static int web_set_regexp(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_login(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);
static int web_set_time_expression(AGENT_RESULT *result, struct web *opt, const char *params, int param_id);

static int web_curl_set_bauth(struct web *opt);
static int web_curl_set_body_write(struct web *opt);
static int web_curl_set_body_write_throw(struct web *opt);
static int web_curl_set_header_write(struct web *opt);
static int web_curl_set_header_write_throw(struct web *opt);

static int web_key_check_regexp(struct web *opt);
static int web_key_check_img(struct web *opt);
static int web_key_check_time(struct web *opt);

#endif  /* HAVE_LIBCURL */

#endif /* ZABBIX_CHECKS_WEB_H */
