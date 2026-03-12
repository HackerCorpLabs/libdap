# DAP Library Development Guidelines

## Table of Contents
1. [Code Style and Naming Conventions](#code-style-and-naming-conventions)
2. [Type Safety and Structure Definitions](#type-safety-and-structure-definitions)
3. [Error Handling](#error-handling)
4. [Testing and Quality Assurance](#testing-and-quality-assurance)
5. [Documentation](#documentation)
6. [Code Organization](#code-organization)
7. [Build System](#build-system)
8. [Protocol Compliance](#protocol-compliance)
9. [Memory Management](#memory-management)
10. [Development Process](#development-process)

## Code Style and Naming Conventions

### Naming Rules
- Use camelCase for all structure members and function names
- Use UPPER_CASE for macros and constants
- Use descriptive names that indicate purpose
- Avoid abbreviations unless they are widely understood
- Be consistent with naming patterns across the codebase

### Code Formatting
- Use 4 spaces for indentation
- Maximum line length of 100 characters
- Use braces for all control structures
- Place opening braces on the same line
- Add spaces around operators
- Use blank lines to separate logical sections

### Example
```c
// Good
typedef struct {
    int variablesReference;    // camelCase
    uint64_t memoryReference;     // camelCase
    bool isEvaluatable;        // camelCase with boolean prefix
} DAPVariable;

// Bad
typedef struct {
    int variables_reference;   // snake_case
    uint64_t  memory_reference;    // snake_case
    bool evaluatable;          // missing boolean prefix
} DAPVariable;
```

## Type Safety and Structure Definitions

### Structure Definitions
- Define all structures in header files
- Use typedef for all structures
- Add static assertions to verify structure sizes
- Document all structure members
- Use consistent types for similar fields

### Type Safety
- Use proper type definitions
- Avoid void* unless absolutely necessary
- Use const where appropriate
- Validate pointer parameters
- Use size_t for sizes and counts

### Example
```c
// Good
DAP_STRUCT_BEGIN(DAPVariable)
    char* name;                ///< Variable name
    char* value;               ///< Variable value as string
    char* type;                ///< Variable type
    int variablesReference;    ///< Reference ID for variables with children
    int namedVariables;        ///< Number of named child variables
    int indexedVariables;      ///< Number of indexed child variables
    char* memoryReference;     ///< Memory reference for memory variables
    bool evaluatable;          ///< Whether the variable can be evaluated
DAP_STRUCT_END(DAPVariable)

// Add validation
bool dap_variable_validate(const DAPVariable* var);
```

## Error Handling

### Error Codes
- Use enums for error codes
- Document all error conditions
- Provide meaningful error messages
- Handle all error cases
- Clean up resources in error cases

### Example
```c
typedef enum {
    DAP_ERROR_NONE = 0,
    DAP_ERROR_INVALID_PARAM,
    DAP_ERROR_MEMORY,
    DAP_ERROR_PROTOCOL,
    DAP_ERROR_IO
} DAPError;

bool dap_function(DAPClient* client, DAPResult* result) {
    if (!client || !result) {
        result->success = false;
        result->message = "Invalid parameters";
        return false;
    }
    // ... implementation
}
```

## Testing and Quality Assurance

### Unit Testing
- Write tests for all functions
- Test error conditions
- Test edge cases
- Use a consistent testing framework
- Document test cases

### Static Analysis
- Use clang-tidy
- Enable all compiler warnings
- Use address sanitizer
- Use undefined behavior sanitizer
- Regular code reviews

### Example
```c
// test_dap_variable.c
void test_dap_variable_creation(void) {
    DAPVariable var = {0};
    TEST_ASSERT(dap_variable_validate(&var));
    // ... more tests
}
```

## Documentation

### Code Documentation
- Use Doxygen-style comments
- Document all public functions
- Document all structures
- Document error conditions
- Provide usage examples

### Example
```c
/**
 * @brief Creates a new DAP variable
 * 
 * @param name Variable name
 * @param value Variable value
 * @param type Variable type
 * @return DAPVariable* New variable or NULL on error
 * 
 * @note Caller must free the returned variable using dap_variable_free()
 */
DAPVariable* dap_variable_create(const char* name, const char* value, const char* type);
```

## Code Organization

### File Structure
- One header file per module
- Separate implementation files
- Clear module boundaries
- Minimal dependencies
- Logical grouping

### Example Structure
```
libdap/
├── include/
│   ├── dap_types.h
│   ├── dap_client.h
│   └── dap_server.h
├── src/
│   ├── dap_types.c
│   ├── dap_client.c
│   └── dap_server.c
└── tests/
    ├── test_types.c
    ├── test_client.c
    └── test_server.c
```

## Build System

### Compiler Flags
- Enable all warnings (-Wall -Wextra)
- Treat warnings as errors (-Werror)
- Enable debug information (-g)
- Use address sanitizer (-fsanitize=address)
- Use undefined behavior sanitizer (-fsanitize=undefined)

### Makefile Rules
- Separate debug and release builds
- Clean build targets
- Test targets
- Documentation targets
- Install targets

## Protocol Compliance

### DAP Protocol
- Follow DAP specification strictly
- Document any deviations
- Validate all messages
- Handle all required fields
- Test protocol compliance

### Example
```c
bool dap_validate_message(const cJSON* message) {
    if (!cJSON_IsObject(message)) return false;
    // ... validation
    return true;
}
```

## Memory Management

### Allocation Rules
- Use consistent allocation patterns
- Document ownership
- Free resources in error cases
- Use RAII-like patterns
- Check for memory leaks

### Example
```c
DAPVariable* dap_variable_create(const char* name, const char* value, const char* type) {
    DAPVariable* var = calloc(1, sizeof(DAPVariable));
    if (!var) return NULL;
    
    var->name = strdup(name);
    var->value = strdup(value);
    var->type = strdup(type);
    
    if (!var->name || !var->value || !var->type) {
        dap_variable_free(var);
        return NULL;
    }
    
    return var;
}
```

## Development Process

### Version Control
- Use meaningful commit messages
- Create feature branches
- Review before merging
- Tag releases
- Document changes

### Code Review
- Review all changes
- Check for style compliance
- Verify error handling
- Test changes
- Document review process

### Continuous Integration
- Automated builds
- Automated testing
- Static analysis
- Memory checking
- Protocol validation

## Tools and Resources

### Recommended Tools
- clang-format for code formatting
- clang-tidy for static analysis
- valgrind for memory checking
- Doxygen for documentation
- CMake for build system

### Example Configuration
```cmake
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Werror")
set(CMAKE_C_FLAGS_DEBUG "${CMAKE_C_FLAGS_DEBUG} -g -fsanitize=address")
set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} -O2")
```

## Conclusion

Following these guidelines will help maintain a high-quality, maintainable codebase. Regular reviews and updates to these guidelines are encouraged as the project evolves. 