#include "stdafx.h"

extern "C"
{
    typedef struct _connection_context_t
    {
        struct tls *tls;
        struct tls_config *config;
    } connection_context_t;
}

static connection_context_t g_conn_context;

hal_error_t hal_rpc_client_transport_init()
{
	// get the IP address from the DKS_HSM_HOST_IP environment variable
	const char *hostip = "10.1.10.9";  // getenv("DKS_HSM_HOST_IP");
	const char *hostname = "dks-hsm";  // getenv("DKS_HSM_HOST_NAME");

	if (hostip == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	if (hostname == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	return hal_rpc_client_transport_init_ip(hostip, hostname);
}

hal_error_t hal_rpc_client_transport_init_ip(const char *hostip, const char *hostname)
{
	struct sockaddr_in server;
	int sock;

	if (hostip == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	if (hostname == NULL) {
		return HAL_ERROR_BAD_ARGUMENTS;
	}

	// start the tls connection
	tls_init();

    g_conn_context.tls = tls_client();
    g_conn_context.config = tls_config_new();

	tls_config_insecure_noverifycert(g_conn_context.config);

	tls_config_insecure_noverifyname(g_conn_context.config);

	tls_configure(g_conn_context.tls, g_conn_context.config);

	sock = socket(AF_INET, SOCK_STREAM, 0);

	server.sin_port = htons(8080);
	server.sin_addr.s_addr = inet_addr(hostip);
	server.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
		return HAL_ERROR_RPC_TRANSPORT;
	}

	if (tls_connect_socket(g_conn_context.tls, sock, hostname) < 0) {
        return HAL_ERROR_RPC_TRANSPORT;
	}

	return HAL_OK;
}

hal_error_t hal_rpc_client_transport_close()
{
	if (g_conn_context.tls != NULL)
	{
		tls_close(g_conn_context.tls);
		tls_free(g_conn_context.tls);

        g_conn_context.tls = NULL;
	}

	if (g_conn_context.config != NULL)
	{
		tls_config_free(g_conn_context.config);
        g_conn_context.config = NULL;
	}

	return HAL_OK;
}


hal_error_t hal_rpc_send(const uint8_t * const buf, const size_t len)
{
	return hal_slip_send(buf, len);
}

hal_error_t hal_rpc_recv(uint8_t * const buf, size_t * const len)
{
	size_t maxlen = *len;
	*len = 0;
	hal_error_t err = hal_slip_recv(buf, len, maxlen);
	return err;
}

/*
* These two are sort of mis-named, fix eventually, but this is what
* the code in slip.c expects.
*/

hal_error_t hal_serial_send_char(const uint8_t c)
{
	if (tls_write(g_conn_context.tls, &c, 1) == 1)
		return HAL_OK;
	else
		return HAL_ERROR_RPC_TRANSPORT;
}

hal_error_t hal_serial_recv_char(uint8_t * const c)
{
	if (tls_read(g_conn_context.tls, c, 1) == 1)
		return HAL_OK;
	else
		return HAL_ERROR_RPC_TRANSPORT;
}
