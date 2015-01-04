
#include <ngx_config.h>
#include <ngx_core.h>



extern ngx_module_t  ngx_core_module;
extern ngx_module_t  ngx_errlog_module;
extern ngx_module_t  ngx_conf_module;
extern ngx_module_t  ngx_events_module;
extern ngx_module_t  ngx_event_core_module;
extern ngx_module_t  ngx_epoll_module;
extern ngx_module_t  ngx_http_module;
extern ngx_module_t  ngx_http_core_module;
extern ngx_module_t  ngx_http_log_module;
extern ngx_module_t  ngx_http_upstream_module;
extern ngx_module_t  ngx_http_static_module;
extern ngx_module_t  ngx_http_index_module;
extern ngx_module_t  ngx_http_limit_req_module;
extern ngx_module_t  ngx_http_map_module;
extern ngx_module_t  ngx_http_split_clients_module;
extern ngx_module_t  ngx_http_referer_module;
extern ngx_module_t  ngx_http_rewrite_module;
extern ngx_module_t  ngx_http_proxy_module;
extern ngx_module_t  ngx_http_browser_module;
extern ngx_module_t  ngx_http_upstream_ip_hash_module;
extern ngx_module_t  ngx_http_portrait_module;
extern ngx_module_t  ngx_http_write_filter_module;
extern ngx_module_t  ngx_http_header_filter_module;
extern ngx_module_t  ngx_http_chunked_filter_module;
extern ngx_module_t  ngx_http_range_header_filter_module;
extern ngx_module_t  ngx_http_headers_filter_module;
extern ngx_module_t  ngx_http_copy_filter_module;
extern ngx_module_t  ngx_http_range_body_filter_module;
extern ngx_module_t  ngx_http_not_modified_filter_module;

ngx_module_t *ngx_modules[] = {
    &ngx_core_module,           //NGX_CORE_MODULE
    &ngx_errlog_module,          //NGX_CORE_MODULE
    &ngx_conf_module,                                   //NGX_CONF_MODULE
    &ngx_events_module,         //NGX_CORE_MODULE
    &ngx_event_core_module,                             //NGX_EVENT_MODULE
    &ngx_epoll_module,                                   //NGX_EVENT_MODULE
    &ngx_http_module,            //NGX_CORE_MODULE
    &ngx_http_core_module,                               //NGX_HTTP_MODULE
    &ngx_http_log_module,        //NGX_HTTP_MODULE
    &ngx_http_upstream_module,  //NGX_HTTP_MODULE
    &ngx_http_static_module,      //NGX_HTTP_MODULE
    &ngx_http_index_module,      //NGX_HTTP_MODULE
    &ngx_http_limit_req_module,   //NGX_HTTP_MODULE
    &ngx_http_map_module,       //NGX_HTTP_MODULE
    &ngx_http_split_clients_module,        //NGX_HTTP_MODULE
    &ngx_http_referer_module,             //NGX_HTTP_MODULE
    &ngx_http_rewrite_module,             //NGX_HTTP_MODULE
    &ngx_http_proxy_module,              //NGX_HTTP_MODULE
    &ngx_http_browser_module,            //NGX_HTTP_MODULE
    &ngx_http_upstream_ip_hash_module,   //NGX_HTTP_MODULE
    &ngx_http_portrait_module,             //NGX_HTTP_MODULE
    &ngx_http_write_filter_module,          //NGX_HTTP_MODULE
    &ngx_http_header_filter_module,        //NGX_HTTP_MODULE
    &ngx_http_chunked_filter_module,       //NGX_HTTP_MODULE
    &ngx_http_range_header_filter_module,  //NGX_HTTP_MODULE
    &ngx_http_headers_filter_module,       //NGX_HTTP_MODULE
    &ngx_http_copy_filter_module,          //NGX_HTTP_MODULE
    &ngx_http_range_body_filter_module,    //NGX_HTTP_MODULE
    &ngx_http_not_modified_filter_module,   //NGX_HTTP_MODULE
    NULL
};

