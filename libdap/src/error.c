/**
 * @file error.c
 * @brief Error handling implementation for the DAP library
 */

#include "dap_error.h"
#include <string.h>

// Static variables for error state
static DAPError last_error = DAP_ERROR_NONE;
static char last_error_message[256] = {0};

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

void dap_error_set(DAPError error, const char* message) {
    last_error = error;
    if (message) {
        strncpy(last_error_message, message, sizeof(last_error_message) - 1);
        last_error_message[sizeof(last_error_message) - 1] = '\0';
    } else {
        strncpy(last_error_message, dap_error_message(error), sizeof(last_error_message) - 1);
        last_error_message[sizeof(last_error_message) - 1] = '\0';
    }
}

DAPError dap_error_get(void) {
    return last_error;
}

const char* dap_error_get_message(void) {
    return last_error_message[0] ? last_error_message : dap_error_message(last_error);
}

void dap_error_clear(void) {
    last_error = DAP_ERROR_NONE;
    last_error_message[0] = '\0';
} 