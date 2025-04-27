#ifndef DAP_VALIDATION_H
#define DAP_VALIDATION_H

#include "dap_error.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Initialize the DAP validation module with the schema file
 * 
 * @param schema_path Path to the DAP schema JSON file
 * @return int DAP_ERROR_SUCCESS on success, error code otherwise
 */
int dap_validation_init(const char* schema_path);

/**
 * @brief Cleanup the DAP validation module
 */
void dap_validation_cleanup(void);

/**
 * @brief Validate a DAP request against the schema
 * 
 * @param request JSON string of the request to validate
 * @return int DAP_ERROR_SUCCESS if valid, error code otherwise
 */
int dap_validate_request(const char* request);

/**
 * @brief Validate a DAP response against the schema
 * 
 * @param response_json JSON string of the response to validate
 * @return int DAP_ERROR_SUCCESS if valid, error code otherwise
 */
int dap_validate_response(const char* response_json);

/**
 * @brief Validate a DAP event against the schema
 * 
 * @param event_json JSON string of the event to validate
 * @return int DAP_ERROR_SUCCESS if valid, error code otherwise
 */
int dap_validate_event(const char* event_json);

/**
 * @brief Get the last validation error message
 * 
 * @return const char* Error message, or NULL if no error
 */
const char* dap_validation_get_error(void);

#ifdef __cplusplus
}
#endif

#endif // DAP_VALIDATION_H 