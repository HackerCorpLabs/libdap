/*
 * Copyright (c) 2025 Ronny Hansen
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/**
 * @file dap_transport.c
 * @brief Transport layer implementation for the DAP library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "dap_transport.h"
#include "dap_error.h"

// Debug logging macro
#define DEBUG_LOG(...) do { \
    fprintf(stderr, "[DAP TRANSPORT %s:%d] ", __func__, __LINE__); \
    fprintf(stderr, __VA_ARGS__); \
    fprintf(stderr, "\n"); \
    fflush(stderr); \
} while(0)

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#else
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h>  // For TCP_NODELAY
#include <unistd.h>
#include <arpa/inet.h>
#endif

DAPTransport* dap_transport_create(const DAPTransportConfig* config) {
    if (!config) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid configuration");
        return NULL;
    }

    DEBUG_LOG("Creating transport with type %d", config->type);
    DAPTransport* transport = malloc(sizeof(DAPTransport));
    if (!transport) {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to allocate transport");
        return NULL;
    }

    transport->config = *config;
    transport->listen_fd = -1;
    transport->client_fd = -1;
    transport->is_server = true;

    return transport;
}

int dap_transport_start(DAPTransport* transport) {
    if (!transport) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    DEBUG_LOG("Starting transport");
    switch (transport->config.type) {
        case DAP_TRANSPORT_TCP: {
            DEBUG_LOG("Creating TCP socket");
            int fd = socket(AF_INET, SOCK_STREAM, 0);
            if (fd < 0) {
                dap_error_set(DAP_ERROR_TRANSPORT, "Failed to create socket");
                return -1;
            }

            // Allow reuse of the address
            int opt = 1;
            if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
                DEBUG_LOG("Failed to set socket option: %s (errno=%d)", strerror(errno), errno);
                close(fd);
                return -1;
            }

            struct sockaddr_in addr;
            memset(&addr, 0, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_addr.s_addr = INADDR_ANY;
            addr.sin_port = htons(transport->config.config.tcp.port);

            DEBUG_LOG("Binding to port %d", transport->config.config.tcp.port);
            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                DEBUG_LOG("Failed to bind socket: %s (errno=%d)", strerror(errno), errno);
                dap_error_set(DAP_ERROR_TRANSPORT, "Failed to bind socket");
                close(fd);
                return -1;
            }

            DEBUG_LOG("Listening for connections");
            if (listen(fd, 5) < 0) {
                dap_error_set(DAP_ERROR_TRANSPORT, "Failed to listen on socket");
                close(fd);
                return -1;
            }

            transport->listen_fd = fd;
            transport->client_fd = -1;
            DEBUG_LOG("TCP transport started successfully");
            break;
        }

        case DAP_TRANSPORT_UNIX: {
            int fd = socket(AF_UNIX, SOCK_STREAM, 0);
            if (fd < 0) {
                dap_error_set(DAP_ERROR_TRANSPORT, "Failed to create socket");
                return -1;
            }

            struct sockaddr_un addr;
            memset(&addr, 0, sizeof(addr));
            addr.sun_family = AF_UNIX;
            strncpy(addr.sun_path, transport->config.config.unix_socket.path,
                   sizeof(addr.sun_path) - 1);

            unlink(transport->config.config.unix_socket.path);

            if (bind(fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
                dap_error_set(DAP_ERROR_TRANSPORT, "Failed to bind socket");
                close(fd);
                return -1;
            }

            if (listen(fd, 5) < 0) {
                dap_error_set(DAP_ERROR_TRANSPORT, "Failed to listen on socket");
                close(fd);
                return -1;
            }

            transport->listen_fd = fd;
            transport->client_fd = -1;
            break;
        }

        case DAP_TRANSPORT_PIPE:
        case DAP_TRANSPORT_STDIO:
            dap_error_set(DAP_ERROR_NOT_IMPLEMENTED, "Transport type not implemented");
            return -1;

        default:
            dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport type");
            return -1;
    }

    return 0;
}

int dap_transport_accept(DAPTransport* transport) {
    if (!transport) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    if (transport->listen_fd < 0) {
        dap_error_set(DAP_ERROR_TRANSPORT, "Transport not started");
        return -1;
    }

    DEBUG_LOG("Waiting for client connection");
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(transport->listen_fd, (struct sockaddr*)&client_addr, &client_len);
    if (client_fd < 0) {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to accept connection");
        return -1;
    }

    transport->client_fd = client_fd;
    
    // Convert IP address to string safely
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str)) == NULL) {
        DEBUG_LOG("Client connected from unknown address");
    } else {
        DEBUG_LOG("Client connected from %s:%d", ip_str, ntohs(client_addr.sin_port));
    }
    
    return 0;
}

int dap_transport_stop(DAPTransport* transport) {
    if (!transport) {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    if (transport->client_fd >= 0) {
        close(transport->client_fd);
        transport->client_fd = -1;
    }

    if (transport->listen_fd >= 0) {
        close(transport->listen_fd);
        transport->listen_fd = -1;
    }

    return 0;
}

void dap_transport_free(DAPTransport* transport) {
    if (!transport) return;

    dap_transport_stop(transport);
    free(transport);
}

int dap_transport_send(DAPTransport* transport, const char* data) {
    if (!transport || !data) {
        DEBUG_LOG("Invalid arguments: transport=%p, data=%p", (void*)transport, (void*)data);
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    if (transport->client_fd < 0) {
        DEBUG_LOG("No client connected (client_fd=%d)", transport->client_fd);
        dap_error_set(DAP_ERROR_TRANSPORT, "No client connected");
        return -1;
    }

    // Disable Nagle's algorithm to ensure immediate sending
    int flag = 1;
    if (setsockopt(transport->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0) {
        DEBUG_LOG("Failed to set TCP_NODELAY: %s (errno=%d)", strerror(errno), errno);
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to set TCP_NODELAY");
        return -1;
    }
    DEBUG_LOG("TCP_NODELAY set successfully");

    // Format the message with DAP header
    char header[64];
    size_t data_len = strlen(data);
    size_t header_len = snprintf(header, sizeof(header),
                             "Content-Length: %zu\r\n\r\n",
                             data_len);
    if (header_len >= sizeof(header)) {
        DEBUG_LOG("Header too long: needed %zu bytes, max is %zu", header_len, sizeof(header));
        dap_error_set(DAP_ERROR_TRANSPORT, "Header too long");
        return -1;
    }

    DEBUG_LOG("Sending message - Header length: %zu, Content length: %zu", header_len, data_len);
    DEBUG_LOG("Header: '%.*s'", (int)header_len, header);
    DEBUG_LOG("Content: '%s'", data);
    
    // Send header
    ssize_t sent = 0;
    size_t total = header_len;
    while (sent < (ssize_t)total) {
        ssize_t result = send(transport->client_fd, header + sent, total - sent, 0);
        if (result < 0) {
            if (errno == EINTR) {
                DEBUG_LOG("Header send interrupted, retrying");
                continue;
            }
            DEBUG_LOG("Failed to send header: %s (errno=%d)", strerror(errno), errno);
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send header");
            return -1;
        }
        sent += result;
        DEBUG_LOG("Header: sent %zd/%zu bytes", sent, total);
    }

    // Send content
    sent = 0;
    total = data_len;
    while (sent < (ssize_t)total) {
        ssize_t result = send(transport->client_fd, data + sent, total - sent, 0);
        if (result < 0) {
            if (errno == EINTR) {
                DEBUG_LOG("Content send interrupted, retrying");
                continue;
            }
            DEBUG_LOG("Failed to send content: %s (errno=%d)", strerror(errno), errno);
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to send content");
            return -1;
        }
        sent += result;
        DEBUG_LOG("Content: sent %zd/%zu bytes", sent, total);
    }

    DEBUG_LOG("Message sent successfully - Total bytes: %zu", header_len + data_len);
    return 0;
}

/**
 * @brief Receive a message from the transport
 * 
 * @param transport The transport to receive from
 * @param message Output parameter for the received message
 * @return int 0 on success, -1 on failure
 */
int dap_transport_receive(DAPTransport* transport, char** message) {
    if (!transport || !message) {
        DEBUG_LOG("Invalid arguments");
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    // Read header first
    char header_buffer[1024];
    ssize_t header_received = recv(transport->client_fd, header_buffer, sizeof(header_buffer) - 1, 0);
    if (header_received < 0) {
        DEBUG_LOG("Failed to receive header: %s", strerror(errno));
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to receive header");
        return -1;
    }
    header_buffer[header_received] = '\0';

    // Parse Content-Length
    char* content_length_str = strstr(header_buffer, "Content-Length: ");
    if (!content_length_str) {
        DEBUG_LOG("Missing Content-Length header in received data");
        dap_error_set(DAP_ERROR_TRANSPORT, "Missing Content-Length header");
        return -1;
    }
    content_length_str += strlen("Content-Length: ");
    size_t content_length = (size_t)atoi(content_length_str);

    // Skip the two newlines after the header
    char* content_start = strstr(header_buffer, "\r\n\r\n");
    if (!content_start) {
        content_start = strstr(header_buffer, "\n\n");
        if (!content_start) {
            DEBUG_LOG("Invalid header format - no delimiter found");
            dap_error_set(DAP_ERROR_TRANSPORT, "Invalid header format");
            return -1;
        }
        content_start += 2;
    } else {
        content_start += 4;
    }

    // Calculate how much of the content we already received in the header buffer
    size_t header_content_len = header_received - (content_start - header_buffer);
    
    // Allocate buffer for full content
    char* buffer = malloc(content_length + 1);
    if (!buffer) {
        DEBUG_LOG("Failed to allocate memory for message");
        dap_error_set(DAP_ERROR_MEMORY, "Failed to allocate message buffer");
        return -1;
    }

    // Copy any content already in header buffer
    if (header_content_len > 0) {
        memcpy(buffer, content_start, header_content_len);
    }

    // If we need more content, read it
    if (header_content_len < content_length) {
        size_t remaining = content_length - header_content_len;
        ssize_t content_received = recv(transport->client_fd, buffer + header_content_len, remaining, 0);
        if (content_received < 0) {
            DEBUG_LOG("Failed to receive content: %s", strerror(errno));
            free(buffer);
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to receive content");
            return -1;
        }
        header_content_len += (size_t)content_received;
    }

    buffer[content_length] = '\0';
    *message = buffer;

    return 0;
} 