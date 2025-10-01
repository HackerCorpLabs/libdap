#include "dap_debugger_files.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <libgen.h>
#include <ctype.h>

FileType detect_file_type(const char* filename) {
    if (!filename) return FILE_TYPE_UNKNOWN;

    // Find the last dot for extension
    const char* ext = strrchr(filename, '.');
    if (!ext) return FILE_TYPE_UNKNOWN;

    // Convert extension to lowercase for comparison
    char lower_ext[16];
    strncpy(lower_ext, ext, sizeof(lower_ext) - 1);
    lower_ext[sizeof(lower_ext) - 1] = '\0';

    for (char* p = lower_ext; *p; p++) {
        *p = tolower(*p);
    }

    // Detect file types
    if (strcmp(lower_ext, ".s") == 0 || strcmp(lower_ext, ".asm") == 0) {
        return FILE_TYPE_ASSEMBLY;
    }
    if (strcmp(lower_ext, ".c") == 0) {
        return FILE_TYPE_C;
    }
    if (strcmp(lower_ext, ".out") == 0 || strcmp(lower_ext, ".bin") == 0 || strcmp(lower_ext, ".exe") == 0) {
        return FILE_TYPE_BINARY;
    }
    if (strcmp(lower_ext, ".map") == 0) {
        return FILE_TYPE_MAP;
    }

    return FILE_TYPE_UNKNOWN;
}

bool file_exists(const char* filepath) {
    if (!filepath) return false;
    struct stat st;
    return stat(filepath, &st) == 0 && S_ISREG(st.st_mode);
}

char* resolve_absolute_path(const char* relative_path) {
    if (!relative_path) return NULL;

    // If already absolute, just duplicate
    if (relative_path[0] == '/') {
        return strdup(relative_path);
    }

    // Get current working directory
    char* cwd = getcwd(NULL, 0);
    if (!cwd) return NULL;

    // Allocate space for absolute path
    size_t abs_len = strlen(cwd) + strlen(relative_path) + 2; // +2 for '/' and '\0'
    char* absolute = malloc(abs_len);
    if (!absolute) {
        free(cwd);
        return NULL;
    }

    snprintf(absolute, abs_len, "%s/%s", cwd, relative_path);
    free(cwd);

    return absolute;
}

char* get_directory(const char* filepath) {
    if (!filepath) return NULL;

    char* path_copy = strdup(filepath);
    if (!path_copy) return NULL;

    char* dir = dirname(path_copy);
    char* result = strdup(dir);
    free(path_copy);

    return result;
}

char* get_base_name(const char* filepath) {
    if (!filepath) return NULL;

    // Get filename without directory
    const char* filename = strrchr(filepath, '/');
    if (filename) {
        filename++; // Skip the '/'
    } else {
        filename = filepath; // No directory part
    }

    // Find the last dot to remove extension
    const char* ext = strrchr(filename, '.');
    if (!ext) {
        return strdup(filename); // No extension
    }

    // Copy everything before the extension
    size_t base_len = ext - filename;
    char* base = malloc(base_len + 1);
    if (!base) return NULL;

    strncpy(base, filename, base_len);
    base[base_len] = '\0';

    return base;
}

FileSet* discover_files(const char* primary_file) {
    if (!primary_file) return NULL;

    FileSet* files = calloc(1, sizeof(FileSet));
    if (!files) return NULL;

    // Resolve to absolute path
    char* abs_primary = resolve_absolute_path(primary_file);
    if (!abs_primary) {
        free_file_set(files);
        return NULL;
    }

    // Detect primary file type
    files->primary_type = detect_file_type(abs_primary);

    // Get directory and base name
    char* dir = get_directory(abs_primary);
    char* base = get_base_name(abs_primary);

    if (!dir || !base) {
        free(abs_primary);
        free(dir);
        free(base);
        free_file_set(files);
        return NULL;
    }

    // Build file paths based on primary file type
    char temp_path[1024];

    switch (files->primary_type) {
        case FILE_TYPE_ASSEMBLY:
            // For .s/.asm files:
            // - source_file = the .s/.asm file itself
            // - program_file = corresponding .out file
            // - map_file = corresponding .map file
            // - debug_type = "ND-100 Assembly"

            files->source_file = strdup(abs_primary);
            files->debug_type = strdup("ND-100 Assembly");
            files->config_name = malloc(strlen(base) + 20);
            sprintf(files->config_name, "Debug %s Assembly", base);

            // Look for .out file
            snprintf(temp_path, sizeof(temp_path), "%s/%s.out", dir, base);
            if (file_exists(temp_path)) {
                files->program_file = strdup(temp_path);
            }

            // Look for .map file
            snprintf(temp_path, sizeof(temp_path), "%s/%s.map", dir, base);
            if (file_exists(temp_path)) {
                files->map_file = strdup(temp_path);
            }
            break;

        case FILE_TYPE_C:
            // For .c/.C files:
            // - source_file = the .c file itself
            // - secondary_source = corresponding .s file (if exists)
            // - program_file = corresponding .out file
            // - debug_type = "C"

            files->source_file = strdup(abs_primary);
            files->debug_type = strdup("C");
            files->config_name = malloc(strlen(base) + 15);
            sprintf(files->config_name, "Debug %s C", base);

            // Look for .s file (generated assembly)
            snprintf(temp_path, sizeof(temp_path), "%s/%s.s", dir, base);
            if (file_exists(temp_path)) {
                files->secondary_source = strdup(temp_path);
            }

            // Look for .out file
            snprintf(temp_path, sizeof(temp_path), "%s/%s.out", dir, base);
            if (file_exists(temp_path)) {
                files->program_file = strdup(temp_path);
            }
            break;

        case FILE_TYPE_BINARY:
            // For .out/.bin/.exe files:
            // - program_file = the binary itself
            // - Try to find corresponding source (.s, .asm, .c)
            // - map_file = corresponding .map file

            files->program_file = strdup(abs_primary);

            // Look for source files (prefer .c, then .s, then .asm)
            snprintf(temp_path, sizeof(temp_path), "%s/%s.c", dir, base);
            if (file_exists(temp_path)) {
                files->source_file = strdup(temp_path);
                files->debug_type = strdup("C");
                files->config_name = malloc(strlen(base) + 15);
                sprintf(files->config_name, "Debug %s C", base);

                // Also look for .s file for C
                snprintf(temp_path, sizeof(temp_path), "%s/%s.s", dir, base);
                if (file_exists(temp_path)) {
                    files->secondary_source = strdup(temp_path);
                }
            } else {
                snprintf(temp_path, sizeof(temp_path), "%s/%s.s", dir, base);
                if (file_exists(temp_path)) {
                    files->source_file = strdup(temp_path);
                    files->debug_type = strdup("ND-100 Assembly");
                    files->config_name = malloc(strlen(base) + 20);
                    sprintf(files->config_name, "Debug %s Assembly", base);
                } else {
                    snprintf(temp_path, sizeof(temp_path), "%s/%s.asm", dir, base);
                    if (file_exists(temp_path)) {
                        files->source_file = strdup(temp_path);
                        files->debug_type = strdup("ND-100 Assembly");
                        files->config_name = malloc(strlen(base) + 20);
                        sprintf(files->config_name, "Debug %s Assembly", base);
                    }
                }
            }

            // Look for .map file
            snprintf(temp_path, sizeof(temp_path), "%s/%s.map", dir, base);
            if (file_exists(temp_path)) {
                files->map_file = strdup(temp_path);
            }
            break;

        default:
            // Unknown file type
            files->debug_type = strdup("Unknown");
            files->config_name = strdup("Debug Unknown");
            break;
    }

    free(abs_primary);
    free(dir);
    free(base);

    return files;
}

void free_file_set(FileSet* files) {
    if (!files) return;

    free(files->program_file);
    free(files->source_file);
    free(files->map_file);
    free(files->secondary_source);
    free(files->debug_type);
    free(files->config_name);
    free(files);
}

void print_file_set(const FileSet* files) {
    if (!files) return;

    printf("Discovered files for debugging:\n");
    printf("  Type: %s\n", files->debug_type ? files->debug_type : "Unknown");
    printf("  Config: %s\n", files->config_name ? files->config_name : "Unnamed");

    if (files->source_file) {
        printf("  Source: %s\n", files->source_file);
    }
    if (files->secondary_source) {
        printf("  Secondary source: %s\n", files->secondary_source);
    }
    if (files->program_file) {
        printf("  Program: %s\n", files->program_file);
    }
    if (files->map_file) {
        printf("  Map: %s\n", files->map_file);
    }
    printf("\n");
}

bool validate_file_set(const FileSet* files) {
    if (!files) return false;

    bool valid = true;

    // Check if source file exists (if specified)
    if (files->source_file && !file_exists(files->source_file)) {
        printf("Error: Source file not found: %s\n", files->source_file);
        valid = false;
    }

    // Check if program file exists (if specified)
    if (files->program_file && !file_exists(files->program_file)) {
        printf("Error: Program file not found: %s\n", files->program_file);
        valid = false;
    }

    // Warn about missing optional files
    if (files->map_file && !file_exists(files->map_file)) {
        printf("Warning: Map file not found: %s\n", files->map_file);
        // Don't set valid = false for map files, they're optional
    }

    if (files->secondary_source && !file_exists(files->secondary_source)) {
        printf("Warning: Secondary source file not found: %s\n", files->secondary_source);
        // Don't set valid = false for secondary source, it's optional
    }

    // Must have at least a source or program file
    if (!files->source_file && !files->program_file) {
        printf("Error: No source or program file specified\n");
        valid = false;
    }

    return valid;
}