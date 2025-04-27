/**
 * @file dap_transport.h
 * @brief Transport layer definitions for the DAP library
 */

#ifndef ND100X_DAP_TRANSPORT_H
#define ND100X_DAP_TRANSPORT_H

#include <stddef.h>
#include <stdbool.h>

/**
 * @brief Transport configuration
 */
typedef struct {
    enum {
        DAP_TRANSPORT_TCP,
        DAP_TRANSPORT_UNIX,
        DAP_TRANSPORT_PIPE,
        DAP_TRANSPORT_STDIO
    } type;
    union {
        struct {
            const char* host;
            int port;
        } tcp;
        struct {
            const char* path;
        } unix_socket;
        struct {
            const char* path;
        } pipe;
    } config;
} DAPTransportConfig;

/**
 * @brief Transport instance
 */
typedef struct DAPTransport {
    DAPTransportConfig config;
    int listen_fd;
    int client_fd;
    bool is_server;
} DAPTransport;

/**
 * @brief Create a new transport instance
 * 
 * @param config Transport configuration
 * @return DAPTransport* New transport instance, or NULL on error
 */
DAPTransport* dap_transport_create(const DAPTransportConfig* config);

/**
 * @brief Start the transport
 * 
 * @param transport Transport instance
 * @return int 0 on success, -1 on error
 */
int dap_transport_start(DAPTransport* transport);

/**
 * @brief Stop the transport
 * 
 * @param transport Transport instance
 * @return int 0 on success, -1 on error
 */
int dap_transport_stop(DAPTransport* transport);

/**
 * @brief Free the transport
 * 
 * @param transport Transport instance
 */
void dap_transport_free(DAPTransport* transport);

/**
 * @brief Send data through the transport
 * 
 * @param transport Transport instance
 * @param data Data to send
 * @return int 0 on success, -1 on error
 */
int dap_transport_send(DAPTransport* transport, const char* data);

/**
 * @brief Receive data from the transport
 * 
 * @param transport Transport instance
 * @param message Output parameter for the received message (caller must free)
 * @return int 0 on success, -1 on error
 */
int dap_transport_receive(DAPTransport* transport, char** message);

/**
 * @brief Accept a new connection on the transport
 * 
 * @param transport Transport instance
 * @return int 0 on success, -1 on error
 */
int dap_transport_accept(DAPTransport* transport);

#endif /* ND100X_DAP_TRANSPORT_H */ 