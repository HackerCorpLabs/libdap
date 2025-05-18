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
#include <netdb.h> // For gethostbyname and struct hostent
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <netinet/tcp.h> // For TCP_NODELAY
#include <arpa/inet.h>   // For inet_ntop
#include <unistd.h>      // For close
#include <sys/select.h>
#include <sys/time.h>
#include "dap_transport.h"
#include "dap_error.h"

#define DEBUG_LOG_ENABLED 1

// Debug logging macro - doesn't check transport->debuglog directly
#define DEBUG_LOG(...)                                                     \
    do                                                                     \
    {                                                                      \
        if (DEBUG_LOG_ENABLED)                                             \
        {                                                                  \
            fprintf(stderr, "[DAP TRANSPORT %s:%d] ", __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                                  \
            fprintf(stderr, "\n");                                         \
            fflush(stderr);                                                \
        }                                                                  \
    } while (0)

// Debug logging macro that also checks transport->debuglog
#define DEBUG_LOG_CHECK(transport, ...)                                    \
    do                                                                     \
    {                                                                      \
        if (DEBUG_LOG_ENABLED && (transport && transport->debuglog))       \
        {                                                                  \
            fprintf(stderr, "[DAP TRANSPORT %s:%d] ", __func__, __LINE__); \
            fprintf(stderr, __VA_ARGS__);                                  \
            fprintf(stderr, "\n");                                         \
            fflush(stderr);                                                \
        }                                                                  \
    } while (0)

DAPTransport *dap_transport_create(const DAPTransportConfig *config)
{
    if (!config)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid configuration");
        return NULL;
    }

    DEBUG_LOG("Creating transport with type %d", config->type);
    DAPTransport *transport = malloc(sizeof(DAPTransport));
    if (!transport)
    {
        dap_error_set(DAP_ERROR_MEMORY, "Failed to allocate transport");
        return NULL;
    }

    transport->config = *config;
    transport->listen_fd = -1;
    transport->client_fd = -1;
    transport->is_server = true;
    transport->debuglog = false; // Initialize debuglog to false by default

    return transport;
}

int dap_transport_start(DAPTransport *transport)
{
    if (!transport)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    DEBUG_LOG("Starting transport");
    switch (transport->config.type)
    {
    case DAP_TRANSPORT_TCP:
    {
        DEBUG_LOG("Creating TCP socket");
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to create socket");
            return -1;
        }

        // Allow reuse of the address
        int opt = 1;
        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0)
        {
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
        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            DEBUG_LOG("Failed to bind socket: %s (errno=%d)", strerror(errno), errno);
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to bind socket");
            close(fd);
            return -1;
        }

        DEBUG_LOG("Listening for connections");
        if (listen(fd, 5) < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to listen on socket");
            close(fd);
            return -1;
        }

        transport->listen_fd = fd;
        transport->client_fd = -1;
        DEBUG_LOG("TCP transport started successfully");
        break;
    }

    case DAP_TRANSPORT_UNIX:
    {
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to create socket");
            return -1;
        }

        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, transport->config.config.unix_socket.path,
                sizeof(addr.sun_path) - 1);

        unlink(transport->config.config.unix_socket.path);

        if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to bind socket");
            close(fd);
            return -1;
        }

        if (listen(fd, 5) < 0)
        {
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

int dap_transport_accept(DAPTransport *transport)
{
    if (!transport)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    if (transport->listen_fd < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Transport not started");
        return -1;
    }

    DEBUG_LOG("Waiting for client connection");

    // Set up select timeout
    fd_set read_fds;
    struct timeval tv;
    FD_ZERO(&read_fds);
    FD_SET(transport->listen_fd, &read_fds);

    // Set timeout to 100ms
    tv.tv_sec = 0;
    tv.tv_usec = 100000; // 100ms in microseconds

    // Wait for connection with timeout
    int select_result = select(transport->listen_fd + 1, &read_fds, NULL, NULL, &tv);
    if (select_result < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Select failed");
        return -1;
    }
    if (select_result == 0)
    {
        // Timeout occurred
        errno = EAGAIN;
        return -1;
    }

    // Connection is available, accept it
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int client_fd = accept(transport->listen_fd, (struct sockaddr *)&client_addr, &client_len);
    if (client_fd < 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to accept connection");
        return -1;
    }

    transport->client_fd = client_fd;

    // Convert IP address to string safely
    char ip_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &client_addr.sin_addr, ip_str, sizeof(ip_str)) == NULL)
    {
        if (transport->debuglog)
        {
            DEBUG_LOG("Client connected from unknown address");
        }
    }
    else
    {
        if (transport->debuglog)
        {
            DEBUG_LOG("Client connected from %s:%d", ip_str, ntohs(client_addr.sin_port));
        }
    }

    return 0;
}

/// @brief Check if the transport is connected
/// @param transport Transport instance
/// @return 0 if not connected, 1 if connected
int dap_transport_is_connected(DAPTransport *transport)
{
    if (!transport)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }
    return transport->client_fd >= 0;
}

/// @brief Stop the transport layer
/// @param transport Transport instance
/// @return 0 on success, -1 on failure
int dap_transport_stop(DAPTransport *transport)
{
    if (!transport)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    if (transport->client_fd >= 0)
    {
        close(transport->client_fd);
        transport->client_fd = -1;
    }

    if (transport->listen_fd >= 0)
    {
        close(transport->listen_fd);
        transport->listen_fd = -1;
    }

    return 0;
}

void dap_transport_free(DAPTransport *transport)
{
    if (!transport)
        return;

    dap_transport_stop(transport);
    free(transport);
}

int dap_transport_send(DAPTransport *transport, const char *message)
{
    if (!transport || !message)
    {
        return -1;
    }

    DEBUG_LOG_CHECK(transport, "Sending message - Length: %zu", strlen(message));

    // Format the message with header - ENSURE PROPER LINE ENDINGS
    char header[64];
    size_t content_length = strlen(message);
    // Use explicit \r\n sequence as bytes, not as string literals that might get converted
    int header_length = snprintf(header, sizeof(header), "Content-Length: %zu%c%c%c%c",
                                 content_length, 13, 10, 13, 10);

    if (header_length < 0 || (size_t)header_length >= sizeof(header))
    {
        DEBUG_LOG_CHECK(transport, "Header too long");
        return -1;
    }

    // Set TCP_NODELAY to ensure timely delivery
    if (transport->config.type == DAP_TRANSPORT_TCP)
    {
        int flag = 1;
        if (setsockopt(transport->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
        {
            DEBUG_LOG_CHECK(transport, "Failed to set TCP_NODELAY: %s", strerror(errno));
        }
        else
        {
            DEBUG_LOG_CHECK(transport, "TCP_NODELAY set successfully");
        }
    }

    // Send message
    ssize_t total_sent = 0;
    ssize_t remaining = header_length;
    const char *curr_ptr = header;

    if (transport->debuglog)
    {
        DEBUG_LOG_CHECK(transport, "------------------------------>>>>>");
        DEBUG_LOG_CHECK(transport, "Sending message - Header length: %d, Content length: %zu",
                        header_length, content_length);
        DEBUG_LOG_CHECK(transport, "Content: '%s'", message);
    }

    // Send header
    while (remaining > 0)
    {
        ssize_t sent = send(transport->client_fd, curr_ptr, remaining, 0);
        if (sent <= 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            DEBUG_LOG_CHECK(transport, "Failed to send header: %s", strerror(errno));
            return -1;
        }
        total_sent += sent;
        curr_ptr += sent;
        remaining -= sent;
    }

    DEBUG_LOG_CHECK(transport, "Header: sent %zd/%d bytes", total_sent, header_length);

    // Reset for content
    total_sent = 0;
    remaining = content_length;
    curr_ptr = message;

    // Send content
    while (remaining > 0)
    {
        ssize_t sent = send(transport->client_fd, curr_ptr, remaining, 0);
        if (sent <= 0)
        {
            if (errno == EINTR)
            {
                continue;
            }
            DEBUG_LOG_CHECK(transport, "Failed to send content: %s", strerror(errno));
            return -1;
        }
        total_sent += sent;
        curr_ptr += sent;
        remaining -= sent;
    }

    DEBUG_LOG_CHECK(transport, "Content: sent %zd/%zu bytes", total_sent, content_length);
    DEBUG_LOG_CHECK(transport, "Message sent successfully - Total bytes: %zu", header_length + content_length);

    // Force flush the TCP buffer by toggling TCP_NODELAY
    if (transport->config.type == DAP_TRANSPORT_TCP)
    {
        int flag = 0;
        setsockopt(transport->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
        flag = 1;
        setsockopt(transport->client_fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));

        // Force a small write to trigger immediate flush
        char flush_byte = 0;
        send(transport->client_fd, &flush_byte, 0, 0);

        DEBUG_LOG_CHECK(transport, "Socket flush completed");
    }

    return 0;
}

/**
 * @brief Check if a file descriptor has an error condition
 *
 * @param fd File descriptor to check
 * @param timeout_ms Timeout in milliseconds
 * @return true if error condition exists, false otherwise
 */
static bool check_fd_error(int fd, int timeout_ms)
{
    fd_set error_fds;
    struct timeval tv;

    // Initialize the file descriptor set
    FD_ZERO(&error_fds);
    FD_SET(fd, &error_fds);

    // Set timeout
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    // Check for error condition using select
    int result = select(fd + 1, NULL, NULL, &error_fds, &tv);

    // Return true if select indicates an error condition
    return (result > 0 && FD_ISSET(fd, &error_fds));
}

/**
 * @brief Check if a file descriptor has data available to read
 *
 * @param fd File descriptor to check
 * @param timeout_ms Timeout in milliseconds
 * @return true if data is available to read, false otherwise
 */
static bool check_fd_readable(int fd, int timeout_ms)
{
    fd_set read_fds;
    struct timeval tv;

    // Initialize the file descriptor set
    FD_ZERO(&read_fds);
    FD_SET(fd, &read_fds);

    // Set timeout
    tv.tv_sec = timeout_ms / 1000;
    tv.tv_usec = (timeout_ms % 1000) * 1000;

    // Check for readability using select
    int result = select(fd + 1, &read_fds, NULL, NULL, &tv);

    // Return true if select indicates data is available to read
    return (result > 0 && FD_ISSET(fd, &read_fds));
}

int try_receive_message(DAPTransport *transport, char *buf, int maxlen, bool readHeader)
{
    int bufcnt = 0;
    char smallbuf[1]; // We only need 1 byte at a time

    while (true)
    {    
        ssize_t rcvcnt = recv(transport->client_fd, smallbuf, 1, 0);
        if (rcvcnt <= 0)
        {
            return -1;
        }
        printf("%c", smallbuf[0]);
        buf[bufcnt++] = smallbuf[0];

        // Detect end of header
        if (readHeader)
        {
            if (bufcnt >= 4)
            {
                // Check the last 4 bytes in the main buffer for \r\n\r\n
                if (buf[bufcnt - 4] == '\r' &&
                    buf[bufcnt - 3] == '\n' &&
                    buf[bufcnt - 2] == '\r' &&
                    buf[bufcnt - 1] == '\n')
                {
                    break;
                }

                // In header, if we cannot find the end of the header, return an error
                if (bufcnt >= maxlen)
                    return -1;
            }
        }
        else
        {
            // Read until we have maxlen bytes when receiving body
            if (bufcnt >= maxlen)
                break;
        }
    }
    buf[bufcnt] = '\0';
    return bufcnt;
    
}

/**
 * @brief Receive a message from the transport
 *
 * @param transport The transport to receive from
 * @param message Output parameter for the received message
 * @return int 0 on success, -1 on failure
 */
int dap_transport_receive(DAPTransport *transport, char **message)
{
    if (!transport || !message)
    {
        if (transport && transport->debuglog)
        {
            DEBUG_LOG_CHECK(transport, "Invalid arguments");
        }
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid arguments");
        return -1;
    }

    if (check_fd_error(transport->client_fd, 10))
    {
        return -1;
    }

    if (!check_fd_readable(transport->client_fd, 10))
    {
        return 0;
    }

    // Read header first
    char header_buffer[1024];
    int header_received = try_receive_message(transport, header_buffer, sizeof(header_buffer), true);
    if (header_received <= 0)
    {
        DEBUG_LOG_CHECK(transport, "Failed to receive header: %s", strerror(errno));
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to receive header");
        return -1;
    }

    // Parse Content-Length
    char *content_length_str = strstr(header_buffer, "Content-Length: ");
    if (!content_length_str)
    {
        DEBUG_LOG_CHECK(transport, "Missing Content-Length header in received data");
        dap_error_set(DAP_ERROR_TRANSPORT, "Missing Content-Length header");
        return -1;
    }
    content_length_str += strlen("Content-Length: ");
    size_t content_length = (size_t)atoi(content_length_str);

    // Validate content length to prevent overflow
    if (content_length > 10 * 1024 * 1024)
    { // Limit to 10MB to prevent malicious inputs
        DEBUG_LOG_CHECK(transport, "Content length too large: %zu", content_length);
        dap_error_set(DAP_ERROR_TRANSPORT, "Content length too large");
        return -1;
    }

    // Skip the two newlines after the header
    char *content_start = strstr(header_buffer, "\r\n\r\n");
    if (!content_start)
    {
        content_start = strstr(header_buffer, "\n\n");
        if (!content_start)
        {
            DEBUG_LOG_CHECK(transport, "Invalid header format - no delimiter found");
            dap_error_set(DAP_ERROR_TRANSPORT, "Invalid header format");
            return -1;
        }
        content_start += 2;
    }
    else
    {
        content_start += 4;
    }

    // Calculate how much of the content we already received in the header buffer
    size_t header_content_len = header_received - (content_start - header_buffer);

    // Make sure we don't exceed the header buffer
    if (header_content_len > (size_t)header_received)
    {
        DEBUG_LOG_CHECK(transport, "Invalid header format - content calculation error");
        dap_error_set(DAP_ERROR_TRANSPORT, "Invalid header format");
        return -1;
    }

    // Allocate buffer for full content with space for null terminator
    char *buffer = malloc(content_length + 1);
    if (!buffer)
    {
        DEBUG_LOG_CHECK(transport, "Failed to allocate memory for message");
        dap_error_set(DAP_ERROR_MEMORY, "Failed to allocate message buffer");
        return -1;
    }

    ssize_t content_received = try_receive_message(transport, buffer, content_length, false);

    if (content_received < 0)
    {
        DEBUG_LOG_CHECK(transport, "Failed to receive content: %s", strerror(errno));
        free(buffer);
        dap_error_set(DAP_ERROR_TRANSPORT, "Failed to receive content");
        return -1;
    }

    // Ensure null termination
    buffer[content_length] = '\0';
    *message = buffer;

    if (transport->debuglog)
    {
        DEBUG_LOG_CHECK(transport, "<<<<<------------------------------");
        DEBUG_LOG_CHECK(transport, "Received message: %zu bytes", content_length);
        DEBUG_LOG_CHECK(transport, "Message content: %s", buffer);
    }

    return 0;
}

/**
 * @brief Connect to a server (client-side function)
 *
 * @param transport Transport instance
 * @return int 0 on success, -1 on failure
 */
int dap_transport_connect(DAPTransport *transport)
{
    if (!transport)
    {
        dap_error_set(DAP_ERROR_INVALID_ARG, "Invalid transport");
        return -1;
    }

    if (transport->client_fd >= 0)
    {
        dap_error_set(DAP_ERROR_TRANSPORT, "Already connected");
        return -1;
    }

    switch (transport->config.type)
    {
    case DAP_TRANSPORT_TCP:
    {
        // Create socket
        int fd = socket(AF_INET, SOCK_STREAM, 0);
        if (fd < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to create socket");
            return -1;
        }

        // Enable TCP_NODELAY to disable Nagle's algorithm for timely delivery
        int flag = 1;
        if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag)) < 0)
        {
            DEBUG_LOG("Warning: Failed to set TCP_NODELAY: %s", strerror(errno));
        }

        // Set up server address
        struct sockaddr_in server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sin_family = AF_INET;
        server_addr.sin_port = htons(transport->config.config.tcp.port);

        // Get server's IP address from hostname
        struct hostent *server = gethostbyname(transport->config.config.tcp.host);
        if (!server)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Could not resolve hostname");
            close(fd);
            return -1;
        }
        memcpy(&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);

        // Connect to server
        if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to connect to server");
            close(fd);
            return -1;
        }

        transport->client_fd = fd;
        break;
    }

    case DAP_TRANSPORT_UNIX:
    {
        // Create socket
        int fd = socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to create socket");
            return -1;
        }

        // Set up server address
        struct sockaddr_un server_addr;
        memset(&server_addr, 0, sizeof(server_addr));
        server_addr.sun_family = AF_UNIX;
        strncpy(server_addr.sun_path, transport->config.config.unix_socket.path,
                sizeof(server_addr.sun_path) - 1);

        // Connect to server
        if (connect(fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        {
            dap_error_set(DAP_ERROR_TRANSPORT, "Failed to connect to server");
            close(fd);
            return -1;
        }

        transport->client_fd = fd;
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