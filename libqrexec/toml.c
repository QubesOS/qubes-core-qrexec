#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include <errno.h>
#include <stddef.h>
#include <limits.h>

#include "libqrexec-utils.h"
#include "private.h"

// A trivial parser for a subset of TOML
static bool qubes_isspace(unsigned char c) {
    return c == ' ' || c == '\t';
}

enum toml_type {
    TOML_TYPE_INVALID, // error
    TOML_TYPE_BOOL,
    TOML_TYPE_INTEGER,
    TOML_TYPE_STRING,
};

union toml_data {
    char *string; // allocated with malloc()
    bool boolean;
    unsigned long long integer;
};

static enum toml_type parse_toml_value(
    const char *file,
    size_t line,
    unsigned char *value_to_parse,
    union toml_data *value) {
    enum toml_type ty = TOML_TYPE_INVALID;
    char *end = NULL;

    switch (value_to_parse[0]) {
    case '0':
        ty = TOML_TYPE_INTEGER;
        value->integer = 0;
        end = (char *)(value_to_parse + 1);
        break;
    case '1' ... '9':
        ty = TOML_TYPE_INTEGER;
        errno = 0;
        value->integer = strtoull((char *)value_to_parse, &end, 10);
        if (errno) {
            PERROR("%s:%zu: strtoull()", file, line);
            return TOML_TYPE_INVALID;
        }
        break;
    case 't':
        ty = TOML_TYPE_BOOL;
        if (strncmp((char *)value_to_parse, "true", 4) == 0) {
            value->boolean = true;
            end = (char *)(value_to_parse + 4);
            break;
        } else {
            LOG(ERROR, "%s:%zu: Unexpected unquoted string", file, line);
            return TOML_TYPE_INVALID;
        }
    case 'f':
        ty = TOML_TYPE_BOOL;
        if (strncmp((char *)value_to_parse, "false", 5) == 0) {
            value->boolean = false;
            end = (char *)(value_to_parse + 5);
            break;
        } else {
            LOG(ERROR, "%s:%zu: Unexpected unquoted string", file, line);
            return TOML_TYPE_INVALID;
        }
    case '"':
        LOG(ERROR, "%s:%zu: Double-quoted strings not implemented, use single quotes", file, line);
        return TOML_TYPE_INVALID;
    case '\'':
        ty = TOML_TYPE_STRING;
        if (value_to_parse[1] == '\'' && value_to_parse[2] == '\'') {
            LOG(ERROR, "%s:%zu: Triple-quoted strings not implemented", file, line);
            return TOML_TYPE_INVALID;
        }
        end = strchr((char *)value_to_parse + 1, '\'');
        if (end == NULL) {
            LOG(ERROR, "%s:%zu: Unterminated quoted string", file, line);
            return TOML_TYPE_INVALID;
        } else {
            size_t to_alloc = (size_t)(end - (char *)value_to_parse);
            value->string = malloc(to_alloc);
            if (value->string == NULL) {
                LOG(ERROR, "%s:%zu: Out of memory copying value", file, line);
                return TOML_TYPE_INVALID;
            }
            memcpy(value->string, value_to_parse + 1, to_alloc - 1);
            value->string[to_alloc - 1] = 0;
            end++;
            break;
        }
    default:
        if (value_to_parse[0] >= ' ' && value_to_parse[0] <= '~') {
            LOG(ERROR, "%s:%zu: Unsupported start of value: '%c'", file, line, value_to_parse[0]);
        } else {
            LOG(ERROR, "%s:%zu: Unsupproted byte at start of value: %d", file, line, value_to_parse[0]);
        }
        return TOML_TYPE_INVALID;
    }
    while (qubes_isspace(*end)) {
        end++;
    }
    if (*end == '\0' || *end == '#')
        return ty;
    if (ty == TOML_TYPE_INTEGER) {
        LOG(ERROR, "%s:%zu: Unexpected junk after integer; note that only decimal integers with no excess leading zeros are supported", file, line);
    } else {
        LOG(ERROR, "%s:%zu: Unexpected junk after value", file, line);
    }
    if (ty == TOML_TYPE_STRING)
        free(value->string);
    return TOML_TYPE_INVALID;
}

static bool qubes_is_key_byte(unsigned char c) {
    switch (c) {
    case '0' ... '9':
    case 'A' ... 'Z':
    case 'a' ... 'z':
    case '.':
    case '-':
    case '_':
        return true;
    default:
        return false;
    }
}

int qubes_toml_config_parse(const char *config_full_path, int *wait_for_session, char **user)
{
    int result = -1; /* assume problem */
    FILE *config_file = fopen(config_full_path, "re");
    if (!config_file) {
        PERROR("Failed to load %s", config_full_path);
        return -1;
    }

    char *current_line = NULL;
    size_t lineno = 0;
    size_t bufsize = 0;
    ssize_t signed_linelen;
    bool seen_wait_for_session = false;
    bool seen_user = false;
    while ((signed_linelen = getline(&current_line, &bufsize, config_file)) != -1) {
        lineno++;
        /* Other negative values are invalid.  If nothing at all is read that means EOF. */
        if (signed_linelen < 1) {
            LOG(ERROR, "%s:%zu:getline returned invalid value %zd (libc bug?)",
                config_full_path, lineno, signed_linelen);
            abort();
        }
        size_t linelen = (size_t)signed_linelen;
        /* Check for NUL in line */
        if (strlen(current_line) != linelen) {
            LOG(ERROR, "%s:%zu:NUL byte in line", config_full_path, lineno);
            goto bad;
        }

        /* Chop off trailing \n (and \r if present) */
        if (linelen > 0 && current_line[linelen - 1] == '\n') {
            linelen--;
            current_line[linelen] = '\0';
            if (linelen > 0 && current_line[linelen - 1] == '\r') {
                linelen--;
                current_line[linelen] = '\0';
            }
        } else {
            LOG(INFO, "%s:%zu:missing newline at EOF", config_full_path, lineno);
        }
        // Multi-line strings not yet implented, so just chop off trailing whitespace
        while (linelen > 1 && qubes_isspace(current_line[linelen - 1])) {
            linelen--;
            current_line[linelen] = '\0';
        }
        switch (current_line[0]) {
        case '\0':
        case '#':
            // Skip comments and blank lines
            continue;
        case 'a' ... 'z':
        case 'A' ... 'Z':
            break;
        case '[':
            LOG(ERROR, "%s:%zu: TOML section headers not supported", config_full_path, lineno);
            goto bad;
        case ' ':
        case '\t':
            LOG(ERROR, "%s:%zu: Unexpected whitespace at start of line", config_full_path, lineno);
            goto bad;
        default:
            if (current_line[0] > ' ' && current_line[0] <= '~') {
                LOG(ERROR, "%s:%zu: Invalid character '%c' at start of key", config_full_path, lineno, current_line[0]);
            } else {
                LOG(ERROR, "%s:%zu: Invalid byte 0x%x at start of key", config_full_path, lineno, current_line[0]);
            }
            goto bad;
        }
        unsigned char *key_cursor = (unsigned char *)current_line;
        do {
            key_cursor++;
        } while (qubes_is_key_byte(key_cursor[0]));
        int const key_len = key_cursor - (unsigned char *)current_line;
        while (qubes_isspace(key_cursor[0]))
            key_cursor++;
        if (key_cursor[0] != '=') {
            LOG(ERROR, "%s:%zu: Missing '=' after key", config_full_path, lineno);
            goto bad;
        }
        do {
            key_cursor++;
        } while (qubes_isspace(key_cursor[0]));
        current_line[key_len] = '\0';
        union toml_data value;
        enum toml_type ty = parse_toml_value(config_full_path, lineno, key_cursor, &value);

        if (strcmp(current_line, "wait-for-session") == 0) {
            if (seen_wait_for_session) {
                LOG(ERROR, "%s:%zu: Key '%s' appears more than once", config_full_path, lineno, current_line);
                goto bad;
            }
            seen_wait_for_session = true;
            if (ty == TOML_TYPE_BOOL) {
                *wait_for_session = (int)value.boolean;
                continue;
            } else if (ty == TOML_TYPE_INTEGER) {
                if (value.integer < 2) {
                    *wait_for_session = (int)value.integer;
                    continue;
                }
                LOG(ERROR, "Integer value %llu used when a boolean was expected", value.integer);
            } else if (ty == TOML_TYPE_STRING) {
                LOG(ERROR, "String value '%s' not valid for 'wait-for-session'", value.string);
                free(value.string);
                value.string = NULL;
            }
        } else if (strcmp(current_line, "force-user") == 0) {
            if (seen_user) {
                LOG(ERROR, "%s:%zu: Key '%s' appears more than once", config_full_path, lineno, current_line);
                goto bad;
            }
            seen_user = true;
            char *bad_type;
            switch (ty) {
            case TOML_TYPE_INVALID:
                goto bad;
            case TOML_TYPE_BOOL:
                bad_type = "Boolean";
                break;
            case TOML_TYPE_INTEGER:
                bad_type = "Integer";
                break;
            case TOML_TYPE_STRING:
                *user = value.string;
                continue;
            default:
                abort();
            }
            LOG(ERROR, "%s:%zu: %s not valid for user name or user ID", config_full_path, lineno, bad_type);
        } else {
            LOG(ERROR, "%s:%zu: Unsupported key %s", config_full_path, lineno, current_line);
            continue;
        }
        goto bad;
    }

    result = 1;
bad:
    free(current_line);
    fclose(config_file);
    return result;
}
