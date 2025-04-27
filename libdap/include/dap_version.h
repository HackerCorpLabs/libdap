/**
 * @file dap_version.h
 * @brief Version information for the DAP library
 */

#ifndef ND100X_DAP_VERSION_H
#define ND100X_DAP_VERSION_H

/**
 * @brief DAP version major number
 */
#define DAP_VERSION_MAJOR 1

/**
 * @brief DAP version minor number
 */
#define DAP_VERSION_MINOR 0

/**
 * @brief DAP version patch number
 */
#define DAP_VERSION_PATCH 0

/**
 * @brief DAP version string
 */
#define DAP_VERSION_STRING "1.0.0"

/**
 * @brief Get DAP version major number
 * 
 * @return int Version major number
 */
int dap_version_major(void);

/**
 * @brief Get DAP version minor number
 * 
 * @return int Version minor number
 */
int dap_version_minor(void);

/**
 * @brief Get DAP version patch number
 * 
 * @return int Version patch number
 */
int dap_version_patch(void);

/**
 * @brief Get DAP version string
 * 
 * @return const char* Version string
 */
const char* dap_version_string(void);

#endif /* ND100X_DAP_VERSION_H */ 