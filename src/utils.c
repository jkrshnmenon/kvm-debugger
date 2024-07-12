#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include "utils.h"

#define LOG_LEVEL_DEBUG 0
#define LOG_LEVEL_INFO 1
#define LOG_LEVEL_WARN 2
#define LOG_LEVEL_ERROR 3

#define CUR_LOG_LEVEL LOG_LEVEL_DEBUG

void *bss_addr(pid_t child) {
    char fname[100];
    snprintf(fname, 100, "/proc/%d/maps", child);
    FILE *fp = fopen(fname, "r");
    if ( fp == NULL) {
        perror("fopen");
        exit(EXIT_FAILURE);
    }
    char line[256];
    char address[32], perms[5];
    while (fgets(line, sizeof(line), fp)) {

        // Scan the address and permission fields from the line
        sscanf(line, "%31s %4s", address, perms);

        // Check if the permissions field is rw-p
        if (strcmp(perms, "rw-p") == 0)
            break;
    }
    char *ptr = strchr(address, '-');
    if ( ptr != NULL ) {
        *ptr = '\0';
	unsigned long ret_val = strtoul(address, NULL, 16);
        return (void *)ret_val+0x300;
    }
    return NULL;
}

void log_debug(FILE *stream, const char *format, ...) {
    if (CUR_LOG_LEVEL > LOG_LEVEL_DEBUG) {
        return;
    }
    va_list args;
    printf("%s", BLUE);
    printf("[DEBUG] ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("%s", RESET);
}

void log_info(FILE *stream, const char *format, ...) {
    if (CUR_LOG_LEVEL > LOG_LEVEL_INFO) {
        return;
    }
    va_list args;
    printf("%s", GREEN);
    printf("[INFO] ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("%s", RESET);
}

void log_warn(FILE *stream, const char *format, ...) {
    if (CUR_LOG_LEVEL > LOG_LEVEL_WARN) {
        return;
    }
    va_list args;
    printf("%s", YELLOW);
    printf("[WARN] ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("%s", RESET);
}

void log_error(FILE *stream, const char *format, ...) {
    if (CUR_LOG_LEVEL > LOG_LEVEL_ERROR) {
        return;
    }
    va_list args;
    printf("%s", RED);
    printf("[ERROR] ");
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    printf("%s", RESET);
}
