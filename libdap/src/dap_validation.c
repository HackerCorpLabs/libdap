#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <cjson/cJSON.h>
#include "dap_validation.h"
#include "dap_error.h"

// Schema validation context
typedef struct {
    cJSON* schema;
    char* schema_path;
    char* last_error;
} DAPValidationContext;

static DAPValidationContext validation_context = {0};

// Helper function to resolve a schema reference
static const cJSON* resolve_ref(const char* ref) {
    if (!ref || ref[0] != '#') {
        return NULL;
    }

    // Skip the initial #/
    const char* ptr = ref + 1;
    if (*ptr == '/') ptr++;

    // Split the path and traverse the schema
    const cJSON* target = validation_context.schema;
    char* path = strdup(ptr);
    if (!path) {
        return NULL;
    }

    char* token = strtok(path, "/");
    while (token && target) {
        if (strcmp(token, "definitions") == 0) {
            target = cJSON_GetObjectItem(target, "definitions");
        } else {
            target = cJSON_GetObjectItem(target, token);
        }
        token = strtok(NULL, "/");
    }

    free(path);
    return target;
}

static void log_validation_step(const char* step, const char* message) {
    printf("[VALIDATION] %s: %s\n", step, message);
}

static void log_schema_validation(const char* type, const char* field, const char* value) {
    printf("[SCHEMA] Validating %s field '%s' with value '%s'\n", type, field, value);
}

static void log_schema_error(const char* field, const char* error) {
    printf("[SCHEMA ERROR] Field '%s': %s\n", field, error);
}

// Helper function to validate a JSON object against a schema
static int validate_against_schema(const cJSON* instance, const cJSON* schema) {
    if (!instance || !schema) {
        log_validation_step("Schema Validation", "Invalid input parameters");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Invalid arguments");
        return DAP_ERROR_INVALID_ARG;
    }

    // Handle $ref first to resolve the base schema
    const cJSON* ref = cJSON_GetObjectItem(schema, "$ref");
    if (ref && cJSON_IsString(ref)) {
        const cJSON* target = resolve_ref(ref->valuestring);
        if (!target) {
            log_schema_error("$ref", "Invalid schema reference");
            if (validation_context.last_error) free(validation_context.last_error);
            validation_context.last_error = strdup("Invalid schema reference");
            return DAP_ERROR_INVALID_FORMAT;
        }
        // Validate against the referenced schema first
        int result = validate_against_schema(instance, target);
        if (result != DAP_ERROR_NONE) {
            return result;
        }
    }

    // Handle allOf (inheritance) next
    const cJSON* allOf = cJSON_GetObjectItem(schema, "allOf");
    if (allOf && cJSON_IsArray(allOf)) {
        cJSON* subschema;
        cJSON_ArrayForEach(subschema, allOf) {
            int result = validate_against_schema(instance, subschema);
            if (result != DAP_ERROR_NONE) {
                return result;
            }
        }
    }

    // Check type
    const cJSON* type = cJSON_GetObjectItem(schema, "type");
    if (type && cJSON_IsString(type)) {
        log_schema_validation("type", "type", type->valuestring);
        if (strcmp(type->valuestring, "object") == 0 && !cJSON_IsObject(instance)) {
            log_schema_error("type", "Expected object type");
            if (validation_context.last_error) free(validation_context.last_error);
            validation_context.last_error = strdup("Expected object type");
            return DAP_ERROR_INVALID_FORMAT;
        }
        if (strcmp(type->valuestring, "string") == 0 && !cJSON_IsString(instance)) {
            log_schema_error("type", "Expected string type");
            if (validation_context.last_error) free(validation_context.last_error);
            validation_context.last_error = strdup("Expected string type");
            return DAP_ERROR_INVALID_FORMAT;
        }
        if (strcmp(type->valuestring, "number") == 0 && !cJSON_IsNumber(instance)) {
            log_schema_error("type", "Expected number type");
            if (validation_context.last_error) free(validation_context.last_error);
            validation_context.last_error = strdup("Expected number type");
            return DAP_ERROR_INVALID_FORMAT;
        }
        if (strcmp(type->valuestring, "boolean") == 0 && !cJSON_IsBool(instance)) {
            log_schema_error("type", "Expected boolean type");
            if (validation_context.last_error) free(validation_context.last_error);
            validation_context.last_error = strdup("Expected boolean type");
            return DAP_ERROR_INVALID_FORMAT;
        }
    }

    // Check required properties
    const cJSON* required = cJSON_GetObjectItem(schema, "required");
    if (required && cJSON_IsArray(required)) {
        log_validation_step("Required Fields", "Checking required fields");
        cJSON* req;
        cJSON_ArrayForEach(req, required) {
            if (cJSON_IsString(req)) {
                const cJSON* prop = cJSON_GetObjectItem(instance, req->valuestring);
                if (!prop) {
                    log_schema_error(req->valuestring, "Required field missing");
                    if (validation_context.last_error) free(validation_context.last_error);
                    validation_context.last_error = malloc(256);
                    if (validation_context.last_error) {
                        snprintf(validation_context.last_error, 255, "Missing required property: %s", req->valuestring);
                    }
                    return DAP_ERROR_INVALID_FORMAT;
                }
            }
        }
    }

    // Check enum for string values
    const cJSON* enum_values = cJSON_GetObjectItem(schema, "enum");
    if (enum_values && cJSON_IsArray(enum_values) && cJSON_IsString(instance)) {
        log_validation_step("Enum Check", "Validating enum values");
        int valid = 0;
        cJSON* value;
        cJSON_ArrayForEach(value, enum_values) {
            if (cJSON_IsString(value) && strcmp(instance->valuestring, value->valuestring) == 0) {
                valid = 1;
                break;
            }
        }
        if (!valid) {
            log_schema_error("enum", "Invalid enum value");
            if (validation_context.last_error) free(validation_context.last_error);
            validation_context.last_error = malloc(256);
            if (validation_context.last_error) {
                snprintf(validation_context.last_error, 255, "Invalid enum value: %s", instance->valuestring);
            }
            return DAP_ERROR_INVALID_FORMAT;
        }
    }

    // Check properties
    const cJSON* properties = cJSON_GetObjectItem(schema, "properties");
    if (properties && cJSON_IsObject(properties)) {
        log_validation_step("Properties", "Validating properties");
        const cJSON* prop = NULL;
        cJSON_ArrayForEach(prop, instance) {
            const cJSON* prop_schema = cJSON_GetObjectItem(properties, prop->string);
            if (prop_schema) {
                log_schema_validation("property", prop->string, 
                    prop->valuestring ? prop->valuestring : "non-string value");
                
                int result = validate_against_schema(prop, prop_schema);
                if (result != DAP_ERROR_NONE) {
                    return result;
                }
            }
        }
    }

    return DAP_ERROR_NONE;
}

// Initialize validation context with schema
int dap_validation_init(const char* schema_path) {
    if (validation_context.schema) {
        return DAP_ERROR_INVALID_STATE;
    }

    FILE* fp = fopen(schema_path, "r");
    if (!fp) {
        return DAP_ERROR_INVALID_ARG;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(fp);
        return DAP_ERROR_INVALID_ARG;
    }

    size_t size = (size_t)file_size;
    char* buffer = malloc(size + 1);
    if (!buffer) {
        fclose(fp);
        return DAP_ERROR_MEMORY;
    }

    size_t bytes_read = fread(buffer, 1, size, fp);
    fclose(fp);

    if (bytes_read != size) {
        free(buffer);
        return DAP_ERROR_INVALID_ARG;
    }
    buffer[size] = '\0';

    validation_context.schema = cJSON_Parse(buffer);
    free(buffer);

    if (!validation_context.schema) {
        return DAP_ERROR_PARSE_ERROR;
    }

    validation_context.schema_path = strdup(schema_path);
    if (!validation_context.schema_path) {
        cJSON_Delete(validation_context.schema);
        validation_context.schema = NULL;
        return DAP_ERROR_MEMORY;
    }

    validation_context.last_error = NULL;
    return DAP_ERROR_NONE;
}

// Cleanup validation context
void dap_validation_cleanup(void) {
    if (validation_context.schema) {
        cJSON_Delete(validation_context.schema);
        validation_context.schema = NULL;
    }
    if (validation_context.schema_path) {
        free(validation_context.schema_path);
        validation_context.schema_path = NULL;
    }
    if (validation_context.last_error) {
        free(validation_context.last_error);
        validation_context.last_error = NULL;
    }
}

// Validate a DAP response message
int dap_validate_response(const char* response) {
    log_validation_step("Response Validation", "Starting response validation");
    
    if (!validation_context.schema) {
        log_validation_step("Schema", "Response schema not found");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Validation not initialized");
        return DAP_ERROR_INVALID_STATE;
    }

    cJSON* json = cJSON_Parse(response);
    if (!json) {
        log_validation_step("Response Validation", "Invalid JSON format");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Invalid JSON");
        return DAP_ERROR_PARSE_ERROR;
    }

    // Get the Response schema
    const cJSON* response_schema = cJSON_GetObjectItem(validation_context.schema, "definitions");
    if (response_schema) {
        response_schema = cJSON_GetObjectItem(response_schema, "Response");
    }

    if (!response_schema) {
        log_validation_step("Schema", "Response schema not found");
        cJSON_Delete(json);
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Response schema not found");
        return DAP_ERROR_INVALID_FORMAT;
    }

    int result = validate_against_schema(json, response_schema);
    cJSON_Delete(json);
    return result;
}

// Validate a DAP event message
int dap_validate_event(const char* event) {
    log_validation_step("Event Validation", "Starting event validation");
    
    if (!validation_context.schema) {
        log_validation_step("Schema", "Event schema not found");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Validation not initialized");
        return DAP_ERROR_INVALID_STATE;
    }

    cJSON* json = cJSON_Parse(event);
    if (!json) {
        log_validation_step("Event Validation", "Invalid JSON format");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Invalid JSON");
        return DAP_ERROR_PARSE_ERROR;
    }

    // Get the Event schema
    const cJSON* event_schema = cJSON_GetObjectItem(validation_context.schema, "definitions");
    if (event_schema) {
        event_schema = cJSON_GetObjectItem(event_schema, "Event");
    }

    if (!event_schema) {
        log_validation_step("Schema", "Event schema not found");
        cJSON_Delete(json);
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Event schema not found");
        return DAP_ERROR_INVALID_FORMAT;
    }

    int result = validate_against_schema(json, event_schema);
    cJSON_Delete(json);
    return result;
}

// Validate a DAP request message
int dap_validate_request(const char* request) {
    log_validation_step("Request Validation", "Starting request validation");
    
    if (!validation_context.schema) {
        log_validation_step("Schema", "Request schema not found");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Validation not initialized");
        return DAP_ERROR_INVALID_STATE;
    }

    cJSON* json = cJSON_Parse(request);
    if (!json) {
        log_validation_step("Request Validation", "Invalid JSON format");
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Invalid JSON");
        return DAP_ERROR_PARSE_ERROR;
    }

    // Get the Request schema
    const cJSON* request_schema = cJSON_GetObjectItem(validation_context.schema, "definitions");
    if (request_schema) {
        request_schema = cJSON_GetObjectItem(request_schema, "Request");
    }

    if (!request_schema) {
        log_validation_step("Schema", "Request schema not found");
        cJSON_Delete(json);
        if (validation_context.last_error) free(validation_context.last_error);
        validation_context.last_error = strdup("Request schema not found");
        return DAP_ERROR_INVALID_FORMAT;
    }

    int result = validate_against_schema(json, request_schema);
    cJSON_Delete(json);
    return result;
}

// Get validation error message
const char* dap_validation_get_error(void) {
    return validation_context.last_error ? validation_context.last_error : "Unknown validation error";
} 