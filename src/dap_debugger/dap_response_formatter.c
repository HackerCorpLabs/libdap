#include "dap_response_formatter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// Unicode box drawing characters
#define BOX_TOP_LEFT     "┌"
#define BOX_TOP_RIGHT    "┐"
#define BOX_BOTTOM_LEFT  "└"
#define BOX_BOTTOM_RIGHT "┘"
#define BOX_HORIZONTAL   "─"
#define BOX_VERTICAL     "│"
#define BOX_CROSS        "┼"
#define BOX_T_DOWN       "┬"
#define BOX_T_UP         "┴"
#define BOX_T_LEFT       "┤"
#define BOX_T_RIGHT      "├"

// Helper function to calculate optimal column width
static int calculate_column_width(const TableColumn* column, cJSON* data_array) {
    if (!column || !data_array) return abs(column->width);

    // Start with header length
    int min_width = strlen(column->header);

    // Check data in array to find max width needed
    cJSON* row;
    cJSON_ArrayForEach(row, data_array) {
        cJSON* value_obj = cJSON_GetObjectItem(row, column->json_key);
        char value_str[MAX_COLUMN_WIDTH + 1];

        if (cJSON_IsString(value_obj)) {
            strncpy(value_str, cJSON_GetStringValue(value_obj), MAX_COLUMN_WIDTH);
            value_str[MAX_COLUMN_WIDTH] = '\0';
        } else if (cJSON_IsNumber(value_obj)) {
            snprintf(value_str, sizeof(value_str), "%.0f", cJSON_GetNumberValue(value_obj));
        } else if (cJSON_IsBool(value_obj)) {
            strcpy(value_str, cJSON_IsTrue(value_obj) ? "yes" : "no");
        } else {
            strcpy(value_str, "unknown");
        }

        int data_width = strlen(value_str);
        if (data_width > min_width) {
            min_width = data_width;
        }
    }

    // Respect the configured max width
    int configured_width = abs(column->width);
    if (min_width > configured_width) {
        return configured_width; // Use truncation
    }

    return min_width;
}

// Helper function to safely append to output buffer
static bool append_to_output(TableFormatter* formatter, const char* text) {
    if (!formatter || !text) return false;

    size_t text_len = strlen(text);
    if (formatter->output_pos + text_len >= MAX_FORMATTED_OUTPUT - 1) {
        return false; // Buffer overflow protection
    }

    strcpy(formatter->output + formatter->output_pos, text);
    formatter->output_pos += text_len;
    formatter->has_content = true;
    return true;
}

// Helper function to append formatted text
static bool append_formatted(TableFormatter* formatter, const char* format, ...) {
    if (!formatter || !format) return false;

    char buffer[512];
    va_list args;
    va_start(args, format);
    int result = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (result < 0 || result >= sizeof(buffer)) {
        return false;
    }

    return append_to_output(formatter, buffer);
}

// Create table row separator
static bool add_table_separator(TableFormatter* formatter,
                                const TableColumn* columns,
                                int column_count,
                                const int* widths,
                                const char* left,
                                const char* middle,
                                const char* right,
                                const char* cross) {
    if (!append_to_output(formatter, left)) return false;

    for (int i = 0; i < column_count; i++) {
        int width = widths[i];
        for (int j = 0; j < width + 2; j++) {  // +2 for padding
            if (!append_to_output(formatter, BOX_HORIZONTAL)) return false;
        }

        if (i < column_count - 1) {
            if (!append_to_output(formatter, cross)) return false;
        }
    }

    if (!append_to_output(formatter, right)) return false;
    return append_to_output(formatter, "\n");
}

// Create table header
static bool add_table_header(TableFormatter* formatter,
                            const TableColumn* columns,
                            int column_count,
                            const int* widths) {
    // Top border
    if (!add_table_separator(formatter, columns, column_count, widths,
                            BOX_TOP_LEFT, BOX_T_DOWN, BOX_TOP_RIGHT, BOX_T_DOWN)) {
        return false;
    }

    // Header row
    if (!append_to_output(formatter, BOX_VERTICAL)) return false;
    for (int i = 0; i < column_count; i++) {
        int width = widths[i];
        bool left_align = columns[i].width < 0;

        if (!append_to_output(formatter, " ")) return false;

        if (left_align) {
            if (!append_formatted(formatter, "%-*s", width, columns[i].header)) return false;
        } else {
            if (!append_formatted(formatter, "%*s", width, columns[i].header)) return false;
        }

        if (!append_to_output(formatter, " ")) return false;
        if (!append_to_output(formatter, BOX_VERTICAL)) return false;
    }
    if (!append_to_output(formatter, "\n")) return false;

    // Header separator
    return add_table_separator(formatter, columns, column_count, widths,
                              BOX_T_RIGHT, BOX_CROSS, BOX_T_LEFT, BOX_CROSS);
}

// Create table footer
static bool add_table_footer(TableFormatter* formatter,
                            const TableColumn* columns,
                            int column_count,
                            const int* widths) {
    return add_table_separator(formatter, columns, column_count, widths,
                              BOX_BOTTOM_LEFT, BOX_T_UP, BOX_BOTTOM_RIGHT, BOX_T_UP);
}

// Add a data row to the table
static bool add_table_row(TableFormatter* formatter,
                         const TableColumn* columns,
                         int column_count,
                         const int* widths,
                         cJSON* row_data) {
    if (!append_to_output(formatter, BOX_VERTICAL)) return false;

    for (int i = 0; i < column_count; i++) {
        int width = widths[i];
        bool left_align = columns[i].width < 0;

        // Extract value from JSON
        cJSON* value_obj = cJSON_GetObjectItem(row_data, columns[i].json_key);
        char value_str[MAX_COLUMN_WIDTH + 1];

        if (cJSON_IsString(value_obj)) {
            strncpy(value_str, cJSON_GetStringValue(value_obj), MAX_COLUMN_WIDTH);
            value_str[MAX_COLUMN_WIDTH] = '\0';
        } else if (cJSON_IsNumber(value_obj)) {
            snprintf(value_str, sizeof(value_str), "%.0f", cJSON_GetNumberValue(value_obj));
        } else if (cJSON_IsBool(value_obj)) {
            strcpy(value_str, cJSON_IsTrue(value_obj) ? "yes" : "no");
        } else {
            strcpy(value_str, "unknown");
        }

        // Truncate if necessary
        if (columns[i].truncate && strlen(value_str) > width) {
            value_str[width - 3] = '.';
            value_str[width - 2] = '.';
            value_str[width - 1] = '.';
            value_str[width] = '\0';
        }

        if (!append_to_output(formatter, " ")) return false;

        if (left_align) {
            if (!append_formatted(formatter, "%-*s", width, value_str)) return false;
        } else {
            if (!append_formatted(formatter, "%*s", width, value_str)) return false;
        }

        if (!append_to_output(formatter, " ")) return false;
        if (!append_to_output(formatter, BOX_VERTICAL)) return false;
    }

    return append_to_output(formatter, "\n");
}

// Public API implementation
TableFormatter* table_formatter_create(void) {
    TableFormatter* formatter = calloc(1, sizeof(TableFormatter));
    if (formatter) {
        table_formatter_reset(formatter);
    }
    return formatter;
}

void table_formatter_destroy(TableFormatter* formatter) {
    if (formatter) {
        free(formatter);
    }
}

void table_formatter_reset(TableFormatter* formatter) {
    if (formatter) {
        formatter->output[0] = '\0';
        formatter->output_pos = 0;
        formatter->has_content = false;
    }
}

const char* table_formatter_get_output(TableFormatter* formatter) {
    return formatter ? formatter->output : NULL;
}

bool table_formatter_add_title(TableFormatter* formatter, const char* title) {
    if (!formatter || !title) return false;
    return append_formatted(formatter, "\n%s:\n", title);
}

bool table_formatter_add_table(TableFormatter* formatter,
                               const TableColumn* columns,
                               int column_count,
                               cJSON* data_array) {
    if (!formatter || !columns || column_count <= 0 || !cJSON_IsArray(data_array)) {
        return false;
    }

    // Calculate optimal column widths
    int widths[MAX_TABLE_COLUMNS];
    if (column_count > MAX_TABLE_COLUMNS) {
        return false;
    }

    for (int i = 0; i < column_count; i++) {
        widths[i] = calculate_column_width(&columns[i], data_array);
    }

    // Add header
    if (!add_table_header(formatter, columns, column_count, widths)) {
        return false;
    }

    // Add data rows
    cJSON* row;
    cJSON_ArrayForEach(row, data_array) {
        if (!add_table_row(formatter, columns, column_count, widths, row)) {
            return false;
        }
    }

    // Add footer
    if (!add_table_footer(formatter, columns, column_count, widths)) {
        return false;
    }

    return append_to_output(formatter, "\n");
}

// Specific formatters
bool format_threads_response(TableFormatter* formatter, cJSON* body) {
    if (!formatter || !body) return false;

    cJSON* threads_array = cJSON_GetObjectItem(body, "threads");
    if (!cJSON_IsArray(threads_array)) return false;

    static const TableColumn columns[] = {
        {"ID",    "id",    -3,  false},  // Left-aligned, width 3
        {"Name",  "name",  -15, true},   // Left-aligned, width 15, truncate
        {"State", "state", -7,  false}   // Left-aligned, width 7
    };

    if (!table_formatter_add_title(formatter, "Threads")) {
        return false;
    }

    return table_formatter_add_table(formatter, columns, 3, threads_array);
}

bool format_scopes_response(TableFormatter* formatter, cJSON* body) {
    if (!formatter || !body) return false;

    cJSON* scopes_array = cJSON_GetObjectItem(body, "scopes");
    if (!cJSON_IsArray(scopes_array)) return false;

    static const TableColumn columns[] = {
        {"Name",          "name",                 -23, true},
        {"Variables Ref", "variablesReference",   5,   false}, // Right-aligned numbers
        {"Expensive",     "expensive",            -12, false}
    };

    if (!table_formatter_add_title(formatter, "Scopes")) {
        return false;
    }

    return table_formatter_add_table(formatter, columns, 3, scopes_array);
}

bool format_variables_response(TableFormatter* formatter, cJSON* body) {
    if (!formatter || !body) return false;

    cJSON* variables_array = cJSON_GetObjectItem(body, "variables");
    if (!cJSON_IsArray(variables_array)) return false;

    static const TableColumn columns[] = {
        {"Name",  "name",  -15, true},
        {"Value", "value", -23, true},
        {"Type",  "type",  -15, true}
    };

    if (!table_formatter_add_title(formatter, "Variables")) {
        return false;
    }

    return table_formatter_add_table(formatter, columns, 3, variables_array);
}

bool format_stacktrace_response(TableFormatter* formatter, cJSON* body) {
    if (!formatter || !body) return false;

    cJSON* stackframes_array = cJSON_GetObjectItem(body, "stackFrames");
    if (!cJSON_IsArray(stackframes_array)) return false;

    static const TableColumn columns[] = {
        {"Frame", "id",     3,   false}, // Right-aligned
        {"Name",  "name",   -20, true},
        {"Source", "source", -15, true},
        {"Line",  "line",   4,   false}  // Right-aligned
    };

    if (!table_formatter_add_title(formatter, "Stack Trace")) {
        return false;
    }

    return table_formatter_add_table(formatter, columns, 4, stackframes_array);
}

// Simple base64 decoding function
static int base64_decode(const char* input, unsigned char* output, int max_output_len) {
    if (!input || !output) return 0;

    const char* base64_chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int input_len = strlen(input);
    int output_len = 0;
    int i = 0;

    while (i < input_len && output_len < max_output_len - 3) {
        // Get 4 base64 characters
        int values[4] = {0};
        int valid_chars = 0;

        for (int j = 0; j < 4 && i < input_len; j++, i++) {
            if (input[i] == '=') {
                values[j] = 0;
            } else {
                char* pos = strchr(base64_chars, input[i]);
                if (pos) {
                    values[j] = pos - base64_chars;
                    valid_chars++;
                } else {
                    values[j] = 0;
                }
            }
        }

        if (valid_chars >= 2) {
            // Decode 3 bytes from 4 base64 characters
            output[output_len++] = (values[0] << 2) | (values[1] >> 4);
            if (valid_chars >= 3 && output_len < max_output_len) {
                output[output_len++] = (values[1] << 4) | (values[2] >> 2);
            }
            if (valid_chars >= 4 && output_len < max_output_len) {
                output[output_len++] = (values[2] << 6) | values[3];
            }
        }
    }

    return output_len;
}

bool format_readmemory_response(TableFormatter* formatter, cJSON* body) {
    if (!formatter || !body) return false;

    // Get memory data from response
    cJSON* address_obj = cJSON_GetObjectItem(body, "address");
    cJSON* data_obj = cJSON_GetObjectItem(body, "data");
    cJSON* unreadable_obj = cJSON_GetObjectItem(body, "unreadableBytes");

    const char* address = safe_json_string(address_obj, "unknown");
    const char* data_base64 = safe_json_string(data_obj, "");
    int unreadable_bytes = safe_json_int(unreadable_obj, 0);

    if (!table_formatter_add_title(formatter, "Memory Dump")) {
        return false;
    }

    if (!data_base64 || strlen(data_base64) == 0) {
        return append_formatted(formatter, "No memory data available at %s\n", address);
    }

    // Decode base64 data
    unsigned char decoded_data[1024];
    int decoded_len = base64_decode(data_base64, decoded_data, sizeof(decoded_data));

    if (decoded_len == 0) {
        return append_formatted(formatter, "Failed to decode memory data\n");
    }

    // Parse address for display
    unsigned long base_addr = 0;
    if (address[0] == '0' && (address[1] == 'x' || address[1] == 'X')) {
        base_addr = strtoul(address, NULL, 16);
    }

    // Format hex dump
    if (!append_formatted(formatter, "Address: %s (%d bytes", address, decoded_len)) {
        return false;
    }

    if (unreadable_bytes > 0) {
        if (!append_formatted(formatter, ", %d unreadable", unreadable_bytes)) {
            return false;
        }
    }

    if (!append_formatted(formatter, ")\n\n")) {
        return false;
    }

    if (!append_formatted(formatter, "Address  | 00 01 02 03 04 05 06 07 08 09 0a 0b 0c 0d 0e 0f | ASCII\n")) {
        return false;
    }
    if (!append_formatted(formatter, "---------|-------------------------------------------------|----------------\n")) {
        return false;
    }

    // Display memory in hex dump format (16 bytes per line)
    for (int i = 0; i < decoded_len; i += 16) {
        // Print address
        if (!append_formatted(formatter, "%08lx | ", base_addr + i)) {
            return false;
        }

        // Print hex values
        for (int j = 0; j < 16; j++) {
            if (i + j < decoded_len) {
                if (!append_formatted(formatter, "%02x ", decoded_data[i + j])) {
                    return false;
                }
            } else {
                if (!append_formatted(formatter, "   ")) {
                    return false;
                }
            }
        }

        if (!append_formatted(formatter, "| ")) {
            return false;
        }

        // Print ASCII representation
        for (int j = 0; j < 16 && (i + j) < decoded_len; j++) {
            unsigned char c = decoded_data[i + j];
            if (!append_formatted(formatter, "%c", (c >= 32 && c <= 126) ? c : '.')) {
                return false;
            }
        }

        if (!append_formatted(formatter, "\n")) {
            return false;
        }
    }

    return append_formatted(formatter, "\n");
}

// Main dispatcher
bool format_dap_response(TableFormatter* formatter, const char* command, cJSON* body) {
    if (!formatter || !command || !body) return false;

    if (strcmp(command, "threads") == 0) {
        return format_threads_response(formatter, body);
    } else if (strcmp(command, "scopes") == 0) {
        return format_scopes_response(formatter, body);
    } else if (strcmp(command, "variables") == 0) {
        return format_variables_response(formatter, body);
    } else if (strcmp(command, "stackTrace") == 0) {
        return format_stacktrace_response(formatter, body);
    } else if (strcmp(command, "readMemory") == 0) {
        return format_readmemory_response(formatter, body);
    }

    // Fallback: formatted JSON for unknown commands
    char* json_str = cJSON_Print(body);
    if (json_str) {
        bool result = append_formatted(formatter, "\nResponse for %s:\n%s\n", command, json_str);
        free(json_str);
        return result;
    }

    return false;
}

// Utility functions
const char* safe_json_string(cJSON* obj, const char* default_value) {
    if (cJSON_IsString(obj)) {
        return cJSON_GetStringValue(obj);
    }
    return default_value ? default_value : "unknown";
}

int safe_json_int(cJSON* obj, int default_value) {
    if (cJSON_IsNumber(obj)) {
        return (int)cJSON_GetNumberValue(obj);
    }
    return default_value;
}

bool safe_json_bool(cJSON* obj, bool default_value) {
    if (cJSON_IsBool(obj)) {
        return cJSON_IsTrue(obj);
    }
    return default_value;
}