#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>

#define RESET       "\033[0m"
#define BLUE        "\033[34m"
#define GREEN       "\033[32m"
#define YELLOW      "\033[33m"
#define RED         "\033[31m"

void *bss_addr(pid_t child);

void log_debug(FILE *stream, const char *format, ...);

void log_info(FILE *stream, const char *format, ...);

void log_warn(FILE *stream, const char *format, ...);

void log_error(FILE *stream, const char *format, ...);