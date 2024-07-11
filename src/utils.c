#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

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
