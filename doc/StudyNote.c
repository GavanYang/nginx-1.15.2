#ifdef __STUDY_NOTE__

#if 1
ģ�������صĽ׶Σ���11���׶�
=========================================
NGX_HTTP_POST_READ_PHASE > ��ȡ�������ݽ׶�
{
}

---------------------------------------------------------------
NGX_HTTP_SERVER_REWRITE_PHASE > Server�����ַ��д�׶�
{
	ngx_http_rewrite_module,
	
}

---------------------------------------------------------------
NGX_HTTP_FIND_CONFIG_PHASE > ���ò��ҽ׶� /*�����ù��ص��κ�handler */

---------------------------------------------------------------
NGX_HTTP_REWRITE_PHASE > Location�����ַ��д�׶�

---------------------------------------------------------------
NGX_HTTP_POST_REWRITE_PHASE > �����ַ��д�ύ�׶� /*�����ù��ص��κ�handler */

---------------------------------------------------------------
NGX_HTTP_PREACCESS_PHASE > ����Ȩ�޼��׼���׶�
{
	ngx_http_limit_conn_module,
	ngx_http_limit_req_module,
	ngx_http_realip_module,
}

---------------------------------------------------------------
NGX_HTTP_ACCESS_PHASE > ����Ȩ�޼��׶�
{
	ngx_http_access_module,
	ngx_http_auth_basic_module,
	ngx_http_auth_request_module,	
}

---------------------------------------------------------------
NGX_HTTP_POST_ACCESS_PHASE > ����Ȩ���ύ�׶� /*�����ù��ص��κ�handler */

---------------------------------------------------------------
NGX_HTTP_PRECONTENT_PHASE > ������try_files����׶Σ�Ϊ���ʾ�̬�ļ���Դ������
{
	ngx_http_degradation_module,
	ngx_http_mirror_module,
}

---------------------------------------------------------------
NGX_HTTP_CONTENT_PHASE > ���ݲ����׶�
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
NGX_HTTP_LOG_PHASE > ��־ģ�鴦��׶�
{
	ngx_http_log_module,
}



#endif
#endif /* __STUDY_NOTE__ */
