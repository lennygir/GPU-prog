#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "conversion_utils.h"

const uint8_t* hex_to_byte(const char* hex)
{
    size_t len = strlen(hex) / 2;
    uint8_t* byte = (uint8_t *) malloc(len);

    for (int i = 0; i < len; ++i) {
        int allocated = sscanf(hex + 2 * i, "%2hhx", &byte[i]);
        if (allocated != 1) {
            fprintf(stderr, "Error: Invalid hex string - the conversion failed at index %d\n", i * 2);
            exit(1);
        }
    }

    return byte;
}
