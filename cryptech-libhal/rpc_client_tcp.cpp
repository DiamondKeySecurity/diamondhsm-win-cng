#include "stdafx.h"

extern "C"
{
    typedef struct _connection_context_t
    {
        struct tls *tls;
        struct tls_config *config;
    } connection_context_t;
}

hal_error_t hal_rpc_client_transport_init(void **connection_context)
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

	return hal_rpc_client_transport_init_ip(hostip, hostname, connection_context);
}

hal_error_t hal_rpc_client_transport_init_ip(const char *hostip, const char *hostname, void **connection_context)
{
    connection_context_t *context = new connection_context_t;

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

    context->tls = tls_client();
    context->config = tls_config_new();

	tls_config_insecure_noverifycert(context->config);

	tls_config_insecure_noverifyname(context->config);

	tls_configure(context->tls, context->config);

	sock = socket(AF_INET, SOCK_STREAM, 0);

	server.sin_port = htons(8080);
	server.sin_addr.s_addr = inet_addr(hostip);
	server.sin_family = AF_INET;

	if (connect(sock, (struct sockaddr *) &server, sizeof(server)) < 0) {
        delete context;
		return HAL_ERROR_RPC_TRANSPORT;
	}

	if (tls_connect_socket(context->tls, sock, hostname) < 0) {
        delete context;
        return HAL_ERROR_RPC_TRANSPORT;
	}

    *connection_context = context;

	return HAL_OK;
}

hal_error_t hal_rpc_client_transport_close(void *connection_context)
{
    connection_context_t *context = (connection_context_t *)connection_context;
	if (context->tls != NULL)
	{
		tls_close(context->tls);
		tls_free(context->tls);

        context->tls = NULL;
	}

	if (context->config != NULL)
	{
		tls_config_free(context->config);
        context->config = NULL;
	}

    // delete the memory
    delete context;

	return HAL_OK;
}


hal_error_t hal_rpc_send(const void *connection_context, const uint8_t * const buf, const size_t len)
{
	return hal_slip_send(connection_context, buf, len);
}

hal_error_t hal_rpc_recv(const void *connection_context, uint8_t * const buf, size_t * const len)
{
	size_t maxlen = *len;
	*len = 0;
	hal_error_t err = hal_slip_recv(connection_context, buf, len, maxlen);
	return err;
}

/*
* These two are sort of mis-named, fix eventually, but this is what
* the code in slip.c expects.
*/

hal_error_t hal_serial_send_char(const void *connection_context, const uint8_t c)
{
    connection_context_t *context = (connection_context_t *)connection_context;

	if (tls_write(context->tls, &c, 1) == 1)
		return HAL_OK;
	else
		return HAL_ERROR_RPC_TRANSPORT;
}

hal_error_t hal_serial_recv_char(const void *connection_context, uint8_t * const c)
{
    connection_context_t *context = (connection_context_t *)connection_context;

	if (tls_read(context->tls, c, 1) == 1)
		return HAL_OK;
	else
		return HAL_ERROR_RPC_TRANSPORT;
}
