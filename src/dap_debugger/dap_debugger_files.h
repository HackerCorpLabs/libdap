#ifndef DAP_DEBUGGER_FILES_H
#define DAP_DEBUGGER_FILES_H

#include <stdbool.h>

/**
 * @file dap_debugger_files.h
 * @brief File discovery and path resolution for DAP debugger
 */

typedef enum {
    FILE_TYPE_ASSEMBLY,     // .s, .asm files
    FILE_TYPE_C,           // .c, .C files
    FILE_TYPE_BINARY,      // .out, .bin, .exe files
    FILE_TYPE_MAP,         // .map files
    FILE_TYPE_UNKNOWN
} FileType;

typedef struct {
    char* program_file;     // Binary/executable (.out, .bin, .exe)
    char* source_file;      // Source file (.s, .asm, .c, .C)
    char* map_file;         // Map file (.map)
    char* secondary_source; // For C: the .s file, for Assembly: unused
    char* debug_type;       // "ND-100 Assembly", "C", etc.
    char* config_name;      // Display name for configuration
    FileType primary_type;  // Primary file type
} FileSet;

/**
 * @brief Detect file type from extension
 * @param filename File name or path
 * @return FileType enum value
 */
FileType detect_file_type(const char* filename);

/**
 * @brief Check if a file exists
 * @param filepath Path to check
 * @return true if file exists, false otherwise
 */
bool file_exists(const char* filepath);

/**
 * @brief Convert relative path to absolute path
 * @param relative_path Input path (may be relative or absolute)
 * @return Allocated absolute path string (caller must free)
 */
char* resolve_absolute_path(const char* relative_path);

/**
 * @brief Get directory part of a file path
 * @param filepath Input file path
 * @return Allocated directory path (caller must free)
 */
char* get_directory(const char* filepath);

/**
 * @brief Get base name without extension
 * @param filepath Input file path
 * @return Allocated base name (caller must free)
 */
char* get_base_name(const char* filepath);

/**
 * @brief Auto-discover related files based on primary file
 * @param primary_file Main file provided by user
 * @return FileSet structure with discovered files (caller must free with free_file_set)
 */
FileSet* discover_files(const char* primary_file);

/**
 * @brief Free FileSet structure and all its members
 * @param files FileSet to free
 */
void free_file_set(FileSet* files);

/**
 * @brief Print discovered files for user confirmation
 * @param files FileSet to display
 */
void print_file_set(const FileSet* files);

/**
 * @brief Validate that required files exist
 * @param files FileSet to validate
 * @return true if all required files exist, false otherwise
 */
bool validate_file_set(const FileSet* files);

#endif // DAP_DEBUGGER_FILES_H