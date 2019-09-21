#pragma once

hal_error_t hal_rpc_client_transport_init(void **conn);
hal_error_t hal_rpc_client_transport_init_ip(const char *hostip, const char *hostname, void **conn);
hal_error_t hal_rpc_client_transport_close(const void *conn);
hal_error_t hal_serial_send_char(const void *conn, const uint8_t c);
hal_error_t hal_serial_recv_char(const void *conn, uint8_t * const c);