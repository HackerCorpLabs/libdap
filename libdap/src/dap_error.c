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
 * @file dap_error.c
 * @brief Error handling implementation for the DAP library
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dap_error.h"
#include "dap_server.h"

// Static variables for error state
static char error_message[256];
static DAPError last_error = DAP_ERROR_NONE;

/**
 * @brief Get error message for error code
 * 
 * @param error Error code
 * @return const char* Error message
 */
const char* dap_error_message(DAPError error) {
    switch (error) {
        case DAP_ERROR_NONE:
            return "No error";
        case DAP_ERROR_INVALID_ARG:
            return "Invalid argument";
        case DAP_ERROR_MEMORY:
            return "Memory error";
        case DAP_ERROR_INVALID_FORMAT:
            return "Invalid message format";
        case DAP_ERROR_INVALID_COMMAND:
            return "Invalid command";
        case DAP_ERROR_INVALID_RESPONSE:
            return "Invalid response";
        case DAP_ERROR_REQUEST_FAILED:
            return "Request failed";
        case DAP_ERROR_NOT_IMPLEMENTED:
            return "Not implemented";
        case DAP_ERROR_PARSE_ERROR:
            return "Parse error";
        case DAP_ERROR_INVALID_STATE:
            return "Invalid state";
        case DAP_ERROR_TRANSPORT:
            return "Transport error";
        default:
            return "Unknown error";
    }
}

/**
 * @brief Set error message
 * 
 * @param error Error code
 * @param message Error message
 */
void dap_error_set(DAPError code, const char* message) {
    last_error = code;
    if (message) {
        strncpy(error_message, message, sizeof(error_message) - 1);
        error_message[sizeof(error_message) - 1] = '\0';
    } else {
        error_message[0] = '\0';
    }
}

/**
 * @brief Get last error code
 * 
 * @return DAPError Last error code
 */
DAPError dap_error_get(void) {
    return last_error;
}

/**
 * @brief Get last error message
 * 
 * @return const char* Last error message
 */
const char* dap_error_get_message(void) {
    return error_message;
}

/**
 * @brief Clear error state
 */
void dap_error_clear(void) {
    last_error = DAP_ERROR_NONE;
    error_message[0] = '\0';
}

void dap_response_cleanup(DAPResponse* response) {
    if (response) {
        free(response->data);
        free(response->error_message);
        memset(response, 0, sizeof(DAPResponse));
    }
} 