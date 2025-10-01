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
 * @file dap_error.h
 * @brief Debug Adapter Protocol error handling definitions
 * 
 */

#ifndef DAP_ERROR_H
#define DAP_ERROR_H

#include <stdbool.h>
#include "dap_server.h"
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Error codes for DAP operations
 * 
 * These error codes are used throughout the DAP implementation to indicate
 * various error conditions. They are based on the DAP specification and common
 * implementation needs.
 */
typedef enum {
    DAP_ERROR_NONE = 0,                  // No error
    DAP_ERROR_INVALID_ARG = 1,           // Invalid argument provided
    DAP_ERROR_MEMORY = 2,                // Memory allocation or access error
    DAP_ERROR_INVALID_FORMAT = 3,        // Invalid message format
    DAP_ERROR_INVALID_COMMAND = 4,       // Unknown or invalid command
    DAP_ERROR_INVALID_RESPONSE = 5,      // Invalid response format
    DAP_ERROR_REQUEST_FAILED = 6,        // Request failed to execute
    DAP_ERROR_NOT_IMPLEMENTED = 7,       // Feature not implemented
    DAP_ERROR_PARSE_ERROR = 8,           // JSON parse error
    DAP_ERROR_INVALID_STATE = 9,         // Invalid state for operation
    DAP_ERROR_TRANSPORT = 10,            // Transport layer error
    DAP_ERROR_TIMEOUT = 11,              // Operation timed out
    DAP_ERROR_OUT_OF_MEMORY = 12         // Memory allocation failed
} DAPError;

/**
 * @brief Get error message for a given error code
 * 
 * @param error Error code
 * @return const char* Error message
 */
const char* dap_error_message(DAPError error);

/**
 * @brief Set error state with message
 * 
 * @param error Error code
 * @param message Error message
 */
void dap_error_set(DAPError error, const char* message);

/**
 * @brief Get current error code
 * 
 * @return DAPError Current error code
 */
DAPError dap_error_get(void);

/**
 * @brief Get current error message
 * 
 * @return const char* Current error message
 */
const char* dap_error_get_message(void);

/**
 * @brief Clear current error state
 */
void dap_error_clear(void);

/**
 * @brief Cleanup a DAPResponse structure
 * 
 * This function frees the memory allocated for the DAPResponse structure and its
 * associated data.
 * 
 * @param response Pointer to the DAPResponse structure to be cleaned up
 */
void dap_response_cleanup(DAPResponse* response);

#ifdef __cplusplus
}
#endif

#endif /* DAP_ERROR_H */ 

