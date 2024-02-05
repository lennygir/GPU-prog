#ifndef CONVERSION_UTILS_H
#define CONVERSION_UTILS_H

#include <stdint.h>

#ifndef LE
#define LE(p) (((uint32_t)((p)[0])) | ((uint32_t)((p)[1]) << 8) | ((uint32_t)((p)[2]) << 16) | ((uint32_t)((p)[3]) << 24))
#endif

#ifndef FROM_LE
#define FROM_LE(b, i) (b)[0] = i & 0xFF; (b)[1] = (i >> 8) & 0xFF; (b)[2] = (i >> 16) & 0xFF; (b)[3] = (i >> 24) & 0xFF;
#endif

#ifndef ROTL32
#define ROTL32(v, n) ((v) << (n)) | ((v) >> (32 - (n)))
#endif

const uint8_t* hex_to_byte(const char* hex_str);

#endif //CONVERSION_UTILS_H
