#ifndef DAP_RESPONSE_FORMATTER_H
#define DAP_RESPONSE_FORMATTER_H

#include <cjson/cJSON.h>
#include <stdbool.h>
#include <stddef.h>

// Maximum buffer sizes
#define MAX_FORMATTED_OUTPUT 8192
#define MAX_TABLE_COLUMNS 10
#define MAX_COLUMN_WIDTH 50

// Table column definition
typedef struct {
    const char* header;         // Column header text
    const char* json_key;       // JSON key to extract data from
    int width;                  // Column width (negative for left-align, positive for right-align)
    bool truncate;              // Whether to truncate long values
} TableColumn;

// Calculated column widths
typedef struct {
    int* widths;               // Array of actual widths to use
    int count;                 // Number of columns
} CalculatedWidths;

// Table formatter context
typedef struct {
    char output[MAX_FORMATTED_OUTPUT];
    size_t output_pos;
    bool has_content;
} TableFormatter;

// Core table formatting functions
TableFormatter* table_formatter_create(void);
void table_formatter_destroy(TableFormatter* formatter);
void table_formatter_reset(TableFormatter* formatter);
const char* table_formatter_get_output(TableFormatter* formatter);

// Table building functions
bool table_formatter_add_title(TableFormatter* formatter, const char* title);
bool table_formatter_add_table(TableFormatter* formatter,
                               const TableColumn* columns,
                               int column_count,
                               cJSON* data_array);

// Specific DAP response formatters
bool format_threads_response(TableFormatter* formatter, cJSON* body);
bool format_scopes_response(TableFormatter* formatter, cJSON* body);
bool format_variables_response(TableFormatter* formatter, cJSON* body);
bool format_stacktrace_response(TableFormatter* formatter, cJSON* body);
bool format_readmemory_response(TableFormatter* formatter, cJSON* body);

// Main formatter dispatcher
bool format_dap_response(TableFormatter* formatter, const char* command, cJSON* body);

// Utility functions
const char* safe_json_string(cJSON* obj, const char* default_value);
int safe_json_int(cJSON* obj, int default_value);
bool safe_json_bool(cJSON* obj, bool default_value);

#endif // DAP_RESPONSE_FORMATTER_H