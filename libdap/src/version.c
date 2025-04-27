/**
 * @file version.c
 * @brief Version information implementation for the DAP library
 */

#include "dap_version.h"

const char* libdap_get_version_string(void) {
    return DAP_VERSION_STRING;
}

int libdap_get_version_major(void) {
    return DAP_VERSION_MAJOR;
}

int libdap_get_version_minor(void) {
    return DAP_VERSION_MINOR;
}

int libdap_get_version_patch(void) {
    return DAP_VERSION_PATCH;
} 