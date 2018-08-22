#ifdef __STUDY_NOTE__

#if 1
模块所挂载的阶段：共11个阶段
=========================================
NGX_HTTP_POST_READ_PHASE > 读取请求内容阶段
{
}

---------------------------------------------------------------
NGX_HTTP_SERVER_REWRITE_PHASE > Server请求地址重写阶段
{
	ngx_http_rewrite_module,
	
}

---------------------------------------------------------------
NGX_HTTP_FIND_CONFIG_PHASE > 配置查找阶段 /*不调用挂载的任何handler */

---------------------------------------------------------------
NGX_HTTP_REWRITE_PHASE > Location请求地址重写阶段

---------------------------------------------------------------
NGX_HTTP_POST_REWRITE_PHASE > 请求地址重写提交阶段 /*不调用挂载的任何handler */

---------------------------------------------------------------
NGX_HTTP_PREACCESS_PHASE > 访问权限检查准备阶段
{
	ngx_http_limit_conn_module,
	ngx_http_limit_req_module,
	ngx_http_realip_module,
}

---------------------------------------------------------------
NGX_HTTP_ACCESS_PHASE > 访问权限检查阶段
{
	ngx_http_access_module,
	ngx_http_auth_basic_module,
	ngx_http_auth_request_module,	
}

---------------------------------------------------------------
NGX_HTTP_POST_ACCESS_PHASE > 访问权限提交阶段 /*不调用挂载的任何handler */

---------------------------------------------------------------
NGX_HTTP_PRECONTENT_PHASE > 配置项try_files处理阶段，为访问静态文件资源而配置
{
	ngx_http_degradation_module,
	ngx_http_mirror_module,
}

---------------------------------------------------------------
NGX_HTTP_CONTENT_PHASE > 内容产生阶段
{
	ngx_http_autoindex_module,
	ngx_http_dav_module,
	ngx_http_gzip_static_module,
	ngx_http_index_module,
	ngx_http_random_index_module,
	ngx_http_static_module,
	ngx_http_try_files_module,
	
}

---------------------------------------------------------------
NGX_HTTP_LOG_PHASE > 日志模块处理阶段
{
	ngx_http_log_module,
}



#endif
#endif /* __STUDY_NOTE__ */
