#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct portrait {
	ngx_str_t			uid;
	int					size;
} ngx_http_portrait_ctx_t;

typedef struct{
	ngx_flag_t			enable;

	ngx_int_t			uid_idx;
	ngx_int_t			size_idx;
} ngx_http_portrait_loc_conf_t;

static char * ngx_conf_set_portrait_slot
	(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static ngx_int_t ngx_http_portrait_init
	(ngx_conf_t *cf);

static ngx_http_portrait_ctx_t * ngx_http_portrait_create_ctx
	(ngx_http_request_t *r, ngx_http_portrait_loc_conf_t *plcf);

static ngx_int_t ngx_http_portrait_check_ctx
	(ngx_http_portrait_ctx_t *ctx);

static void * ngx_http_portrait_create_loc_conf(ngx_conf_t *cf);

static char * ngx_http_portrait_merge_loc_conf
	(ngx_conf_t *cf, void *parent, void *child);

static ngx_int_t ngx_http_portrait_handler(ngx_http_request_t *r);


static ngx_command_t ngx_http_portrait_commands[] = {
	{   ngx_string("portrait"),
		NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
		ngx_conf_set_portrait_slot,
		NGX_HTTP_LOC_CONF_OFFSET,
		offsetof(ngx_http_portrait_loc_conf_t, enable),
		NULL
	},
};

static ngx_http_module_t ngx_http_portrait_module_ctx = {
	NULL,								/* preconfiguration */
	ngx_http_portrait_init,				/* postconfiguration */

	NULL,								/* create main configuration */
	NULL,								/* init main configuration */

	NULL,								/* create server configuration */
	NULL,								/* merge server configuration */

	ngx_http_portrait_create_loc_conf,	/* create location configration */
	ngx_http_portrait_merge_loc_conf,	/* merge location configration */
};

ngx_module_t  ngx_http_portrait_module = {
	NGX_MODULE_V1,
	&ngx_http_portrait_module_ctx,		/* module context */
	ngx_http_portrait_commands,			/* module directives */
	NGX_HTTP_MODULE,					/* module type */
	NULL,								/* init master */
	NULL,								/* init module */
	NULL,								/* init process */
	NULL,								/* init thread */
	NULL,								/* exit thread */
	NULL,								/* exit process */
	NULL,								/* exit master */
	NGX_MODULE_V1_PADDING
};

/* load the portrait handler */
static ngx_int_t
ngx_http_portrait_init(ngx_conf_t *cf)
{
	ngx_http_handler_pt		*h;
	ngx_http_core_main_conf_t  *cmcf;

	cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

	h = ngx_array_push(&cmcf->phases[NGX_HTTP_CONTENT_PHASE].handlers);
	if (h == NULL) {
		return NGX_ERROR;
	}

	*h = ngx_http_portrait_handler;

	return NGX_OK;
}

/* acquire request arguments */
static ngx_http_portrait_ctx_t *
ngx_http_portrait_create_ctx
(ngx_http_request_t *r, ngx_http_portrait_loc_conf_t *plcf)
{
	ngx_http_portrait_ctx_t *ctx;
	ngx_http_variable_value_t *vv;

	ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_portrait_ctx_t));
	if (NULL == ctx) return NULL;

	vv = ngx_http_get_indexed_variable(r, plcf->uid_idx);
	if (vv == NULL || vv->not_found || vv->len == 0) return NULL;
	if (vv->len < 1 || vv->len > 16) return NULL;

	ngx_str_t tmp;
	tmp.data = vv->data;
	tmp.len = vv->len;
	ctx->uid.data = ngx_pstrdup(r->pool, &tmp);
	ctx->uid.len = vv->len;

	vv = ngx_http_get_indexed_variable(r, plcf->size_idx);
	if (vv == NULL || vv->not_found || vv->len == 0) return NULL;
	ctx->size = ngx_atoi(vv->data, vv->len);

	return ctx;
}

static ngx_int_t
ngx_http_portrait_check_ctx(ngx_http_portrait_ctx_t *ctx)
{
	/* need to check uid & size ?*/

	if (ctx->size != 30 && ctx->size != 50 && ctx->size != 180)
		return NGX_ERROR;

	return NGX_OK;
}

static void align_uid(u_char *uid, ngx_str_t *id)
{
	size_t i, l;
	u_char *p = uid;
	u_char *s = id->data;

	l = 10 - id->len;

	bzero(uid, 16);

	for (i=0; i<10; i++) {
		if (i < l) *p++ = '0';
		else *p++ = *s++;
	}

	if (l > 0) uid[0] = '9';
}

/* fuck! */
static uint32_t sina_hash(const u_char *pstr)
{
	unsigned char ch;
	uint32_t h  = 5381;
	const u_char * s;
	ngx_int_t    len;

	if (!pstr || !*pstr) return 0;

	s = pstr;
	len = ngx_strlen((char *)s);

	while (len > 0)
	{
		ch = *s++ - 'A';
		if (ch <= 'Z' - 'A')
			ch += 'a' - 'A';
		h = ((h << 5) + h) ^ ch;
		--len;
	}
	return h;
}

static void
ngx_http_get_portrait_path
(ngx_http_request_t *r, ngx_str_t *path, ngx_http_portrait_ctx_t *ctx)
{
	u_char *last;
	uint32_t uid_hash;
	u_char uid[16] = {0};

	align_uid(uid, &ctx->uid);
	uid_hash = sina_hash(uid);

	path->data = ngx_palloc(r->pool, 64);

	last = ngx_sprintf(path->data, "/%03d/%03d/%s.01.%d",
			uid_hash % 1000, (uid_hash/1000) % 1000, uid, ctx->size);

	path->len = last - path->data;
}

static void
ngx_http_portrait_default_path
(ngx_http_request_t *r, ngx_str_t *path, ngx_http_portrait_ctx_t *ctx)
{
	u_char *last;
	path->data = ngx_palloc(r->pool, 64);

	path->data = ngx_palloc(r->pool, 64);

	last = ngx_sprintf(path->data, "/images/%d.gif", ctx->size);
	path->len = last - path->data;
}

/* frome src/http/modules/ngx_http_static_module.c */
static ngx_int_t
ngx_http_static_handler(ngx_http_request_t *r)
{
    u_char                    *last, *location;
    size_t                     root, len;
    ngx_str_t                  path;
    ngx_int_t                  rc;
    ngx_uint_t                 level;
    ngx_log_t                 *log;
    ngx_buf_t                 *b;
    ngx_chain_t                out;
    ngx_open_file_info_t       of;
    ngx_http_core_loc_conf_t  *clcf;

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    if (r->uri.data[r->uri.len - 1] == '/') {
        return NGX_DECLINED;
    }

    log = r->connection->log;

    /*
     * ngx_http_map_uri_to_path() allocates memory for terminating '\0'
     * so we do not need to reserve memory for '/' for possible redirect
     */

    last = ngx_http_map_uri_to_path(r, &path, &root, 0);
    if (last == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    path.len = last - path.data;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0,
                   "http filename: \"%s\"", path.data);

    clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);

    ngx_memzero(&of, sizeof(ngx_open_file_info_t));

    of.read_ahead = clcf->read_ahead;
    of.directio = clcf->directio;
    of.valid = clcf->open_file_cache_valid;
    of.min_uses = clcf->open_file_cache_min_uses;
    of.errors = clcf->open_file_cache_errors;
    of.events = clcf->open_file_cache_events;

    if (ngx_open_cached_file(clcf->open_file_cache, &path, &of, r->pool)
        != NGX_OK)
    {
        switch (of.err) {

        case 0:
            return NGX_HTTP_INTERNAL_SERVER_ERROR;

        case NGX_ENOENT:
        case NGX_ENOTDIR:
        case NGX_ENAMETOOLONG:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_NOT_FOUND;
            break;

        case NGX_EACCES:

            level = NGX_LOG_ERR;
            rc = NGX_HTTP_FORBIDDEN;
            break;

        default:

            level = NGX_LOG_CRIT;
            rc = NGX_HTTP_INTERNAL_SERVER_ERROR;
            break;
        }

        if (rc != NGX_HTTP_NOT_FOUND || clcf->log_not_found) {
            ngx_log_error(level, log, of.err,
                          "%s \"%s\" failed", of.failed, path.data);
        }

        return rc;
    }

    r->root_tested = !r->error_page;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, log, 0, "http static fd: %d", of.fd);

    if (of.is_dir) {

        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, log, 0, "http dir");

        r->headers_out.location = ngx_palloc(r->pool, sizeof(ngx_table_elt_t));
        if (r->headers_out.location == NULL) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        len = r->uri.len + 1;

        if (!clcf->alias && clcf->root_lengths == NULL && r->args.len == 0) {
            location = path.data + clcf->root.len;

            *last = '/';

        } else {
            if (r->args.len) {
                len += r->args.len + 1;
            }

            location = ngx_pnalloc(r->pool, len);
            if (location == NULL) {
                return NGX_HTTP_INTERNAL_SERVER_ERROR;
            }

            last = ngx_copy(location, r->uri.data, r->uri.len);

            *last = '/';

            if (r->args.len) {
                *++last = '?';
                ngx_memcpy(++last, r->args.data, r->args.len);
            }
        }

        /*
         * we do not need to set the r->headers_out.location->hash and
         * r->headers_out.location->key fields
         */

        r->headers_out.location->value.len = len;
        r->headers_out.location->value.data = location;

        return NGX_HTTP_MOVED_PERMANENTLY;
    }

#if !(NGX_WIN32) /* the not regular files are probably Unix specific */

    if (!of.is_file) {
        ngx_log_error(NGX_LOG_CRIT, log, 0,
                      "\"%s\" is not a regular file", path.data);

        return NGX_HTTP_NOT_FOUND;
    }

#endif

    if (r->method & NGX_HTTP_POST) {
        return NGX_HTTP_NOT_ALLOWED;
    }

    rc = ngx_http_discard_request_body(r);

    if (rc != NGX_OK) {
        return rc;
    }

    log->action = "sending response to client";

    r->headers_out.status = NGX_HTTP_OK;
    r->headers_out.content_length_n = of.size;
    r->headers_out.last_modified_time = of.mtime;

    if (ngx_http_set_content_type(r) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    if (r != r->main && of.size == 0) {
        return ngx_http_send_header(r);
    }

    r->allow_ranges = 1;

    /* we need to allocate all before the header would be sent */

    b = ngx_pcalloc(r->pool, sizeof(ngx_buf_t));
    if (b == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    b->file = ngx_pcalloc(r->pool, sizeof(ngx_file_t));
    if (b->file == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    rc = ngx_http_send_header(r);

    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return rc;
    }

    b->file_pos = 0;
    b->file_last = of.size;

    b->in_file = b->file_last ? 1: 0;
    b->last_buf = (r == r->main) ? 1: 0;
    b->last_in_chain = 1;

    b->file->fd = of.fd;
    b->file->name = path;
    b->file->log = log;
    b->file->directio = of.is_directio;

    out.buf = b;
    out.next = NULL;

    return ngx_http_output_filter(r, &out);
}

static ngx_int_t
ngx_http_portrait_handler(ngx_http_request_t *r)
{
	ngx_int_t						rc;
	ngx_str_t						path;
	ngx_http_portrait_ctx_t			*ctx;
	ngx_http_core_loc_conf_t		*clcf;
	ngx_http_portrait_loc_conf_t	*plcf;

	if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD|NGX_HTTP_POST))) {
		return NGX_HTTP_NOT_ALLOWED;
	}

	clcf = ngx_http_get_module_loc_conf(r, ngx_http_core_module);
	plcf = ngx_http_get_module_loc_conf(r, ngx_http_portrait_module);

	if (plcf->enable != 1) return NGX_DECLINED;

	ctx = ngx_http_portrait_create_ctx(r, plcf);
	if (NULL == ctx) return NGX_HTTP_BAD_REQUEST;

	if (ngx_http_portrait_check_ctx(ctx) != NGX_OK)
		return NGX_HTTP_BAD_REQUEST;

	ngx_http_get_portrait_path(r, &path, ctx);

	r->uri.data = path.data;
	r->uri.len = path.len;
	rc = ngx_http_static_handler(r);

	if (rc == NGX_HTTP_NOT_FOUND) {
		ngx_http_portrait_default_path(r, &path, ctx);
		rc = ngx_http_internal_redirect(r, &path, NULL);
	}

	return rc;
}

static ngx_str_t ngx_portrait_uid_key	= ngx_string("pt_uid");
static ngx_str_t ngx_portrait_size_key	= ngx_string("pt_size");

static char *
ngx_conf_set_portrait_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
	char * ret;
	ngx_http_portrait_loc_conf_t *plcf = conf;

	ret = ngx_conf_set_flag_slot(cf, cmd, conf);
	if (ret != NGX_CONF_OK) return NGX_CONF_ERROR;

	if (!plcf->enable) return NGX_CONF_OK;

	/* read param */
	plcf->uid_idx = ngx_http_get_variable_index(cf, &ngx_portrait_uid_key);
	plcf->size_idx = ngx_http_get_variable_index(cf, &ngx_portrait_size_key);

	if (plcf->uid_idx == NGX_ERROR || plcf->size_idx == NGX_ERROR)
		return NGX_CONF_ERROR;

	return NGX_CONF_OK;
}

static void * ngx_http_portrait_create_loc_conf(ngx_conf_t *cf)
{
	ngx_http_portrait_loc_conf_t * conf;

	conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_portrait_loc_conf_t));
	if (NULL == conf) return NGX_CONF_ERROR;

	conf->enable = NGX_CONF_UNSET;

	return conf;
}

static char *
ngx_http_portrait_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
	ngx_http_portrait_loc_conf_t *prev = parent;
	ngx_http_portrait_loc_conf_t *conf = child;

	ngx_conf_merge_value(conf->enable, prev->enable, NGX_CONF_UNSET);

	return NGX_CONF_OK;
}
