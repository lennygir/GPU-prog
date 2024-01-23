#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>

#define BLOCK_SIZE 16
#define KEY_SIZE 16

typedef u_int8_t* Aes128Key; // 128 bits (16 bytes)
typedef Aes128Key* Aes128KeyExpanded; // 10 * 128 bits (10 * 16 bytes)
typedef u_int8_t* Aes128Block; // 128 bits (16 bytes)

/*
========================
AES ECB Encryption
========================

Source :
    - Debug : https://www.cryptool.org/en/cto/aes-step-by-step
    - Operations :
        - https://www.youtube.com/watch?v=O4xNJsjtN6E
        - https://www.youtube.com/watch?v=gP4PqVGudtg
        - https://en.wikipedia.org/wiki/Advanced_Encryption_Standard
        - https://engineering.purdue.edu/kak/compsec/NewLectures/Lecture8.pdf
    - Implementation : https://github.com/m3y54m/aes-in-c/blob/main/src/main.c#L452
    - AddRoundKey : https://en.wikipedia.org/wiki/AES_key_schedule

Operations in a round :
    1. SubBytes : Substitude each byte with another byte according to a lookup table
    2. ShiftRows : Shift each row one by one (1st row by 0, 2nd row by 1, 3rd row by 2, 4th row by 3)
        1234 = 1234 (1st row)
        1234 = 2341 (2nd row)
        1234 = 3412 (3rd row)
        1234 = 4123 (4th row)
    3. MixColumns (not last round) : Each column is multiplied by a fixed matrix
    4. AddRoundKey

Number of rounds :
    10 for 128 bit key
    12 for 192 bit key
    14 for 256 bit key

*/

// ***********************
// RCon
// ***********************
u_int8_t RconMatrix[255] = {
        0x8d, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8,
        0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3,
        0x7d, 0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f,
        0x25, 0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d,
        0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab,
        0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d,
        0xfa, 0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25,
        0x4a, 0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01,
        0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d,
        0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa,
        0xef, 0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a,
        0x94, 0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02,
        0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a,
        0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef,
        0xc5, 0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94,
        0x33, 0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb, 0x8d, 0x01, 0x02, 0x04,
        0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f,
        0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5,
        0x91, 0x39, 0x72, 0xe4, 0xd3, 0xbd, 0x61, 0xc2, 0x9f, 0x25, 0x4a, 0x94, 0x33,
        0x66, 0xcc, 0x83, 0x1d, 0x3a, 0x74, 0xe8, 0xcb
};
u_int8_t getRconValue(int index) {
    return RconMatrix[index];
}


// ***********************
// SubBytes
// ***********************

const u_int8_t subBytesMatrix[256] = {
//  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
        0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b ,0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, // 0
        0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59 ,0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, // 1
        0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f ,0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, // 2
        0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96 ,0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, // 3
        0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e ,0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, // 4
        0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc ,0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, // 5
        0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d ,0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, // 6
        0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d ,0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, // 7
        0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97 ,0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, // 8
        0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a ,0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, // 9
        0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06 ,0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, // A
        0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5 ,0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, // B
        0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4 ,0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, // C
        0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03 ,0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, // D
        0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9 ,0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, // E
        0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6 ,0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16  // F
};
u_int8_t getSubBytesValue(int index) {
    return subBytesMatrix[index];
}

const u_int8_t invSubBytesMatrix[256] = {
//  0     1     2     3     4     5     6     7     8     9     A     B     C     D     E     F
        0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38 ,0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, // 0
        0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87 ,0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, // 1
        0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d ,0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, // 2
        0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2 ,0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, // 3
        0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16 ,0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, // 4
        0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda ,0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, // 5
        0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a ,0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, // 6
        0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02 ,0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, // 7
        0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea ,0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, // 8
        0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85 ,0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, // 9
        0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89 ,0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, // A
        0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20 ,0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, // B
        0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31 ,0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, // C
        0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d ,0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, // D
        0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0 ,0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, // E
        0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26 ,0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d  // F
};

u_int8_t getInvSubBytesValue(int index) {
    return invSubBytesMatrix[index];
}

void subBytes(u_int8_t* block) {
    /*

    Substitude each byte of the block with another byte according to a lookup table (a block must be 128 bits)

    01 02 03 04     -->     7c 77 7b f2
    05 06 07 08             6b 6f c5 30
    09 10 11 12             01 67 2b fe
    13 14 15 16             d7 ab 76 ca
    */

    for(int index = 0; index < 16; ++index) {
        block[index] = getSubBytesValue(block[index]);
    }
}

void invSubBytes(u_int8_t* block) {
    /*

    Substitude each byte of the block with the initial byte according to a lookup table (a block must be 128 bits)

    7c 77 7b f2     -->     01 02 03 04
    6b 6f c5 30             05 06 07 08
    01 67 2b fe             09 10 11 12
    d7 ab 76 ca             13 14 15 16

    */
    for(int index = 0; index < 16; ++index) {
        block[index] = getInvSubBytesValue(block[index]);
    }
}

// ***********************
// ShiftRows
// ***********************

void shiftRows(u_int8_t* block) {
    /*

    Shift each line of the block from right to left (a block must be 128 bits)

    01 02 03 04     -->     02 03 04 01
    05 06 07 08             06 07 08 05
    09 10 11 12             12 09 10 11
    13 14 15 16             16 13 14 15
    */

    for(int rowIndex = 0; rowIndex < 4; ++rowIndex) {
        u_int8_t tmp[4] = {0};
        for(int columnIndex = 0; columnIndex < 4; ++columnIndex) {
            tmp[columnIndex] = block[(rowIndex * 5 + columnIndex * 4) % 16];
        }

        for(int columnIndex = 0; columnIndex < 4; ++columnIndex) {
            block[columnIndex * 4 + rowIndex] = tmp[columnIndex];
        }
    }
}

void invShiftRows(u_int8_t* block) {
    /*

    Shift each line of the block from left to right (a block must be 128 bits)

    01 02 03 04     -->     04 01 02 03
    05 06 07 08             08 05 06 07
    09 10 11 12             12 09 10 11
    13 14 15 16             16 13 14 15
    */

    for(int rowIndex = 0; rowIndex < 4; ++rowIndex) {
        u_int8_t tmp[4] = {0};
        for(int columnIndex = 0; columnIndex < 4; ++columnIndex) {
            const int index = columnIndex * 4 + rowIndex;
            tmp[columnIndex] = block[(16 + index - rowIndex * 4) % 16];
        }

        for(int columnIndex = 0; columnIndex < 4; ++columnIndex) {
            block[columnIndex * 4 + rowIndex] = tmp[columnIndex];
        }
    }
}

// ***********************
// MixColumns
// ***********************

u_int8_t galois_multiplication(u_int8_t a, u_int8_t b)
{
    u_int8_t p = 0;
    u_int8_t counter;
    u_int8_t hi_bit_set;
    for (counter = 0; counter < 8; counter++)
    {
        if ((b & 1) == 1)
            p ^= a;
        hi_bit_set = (a & 0x80);
        a <<= 1;
        if (hi_bit_set == 0x80)
            a ^= 0x1b;
        b >>= 1;
    }
    return p;
}

const u_int8_t mixColumnsMatrix[4][4] = {
        {0x02, 0x03, 0x01, 0x01},
        {0x01, 0x02, 0x03, 0x01},
        {0x01, 0x01, 0x02, 0x03},
        {0x03, 0x01, 0x01, 0x02}
};

void mixColumns(u_int8_t* block) {
    /*

    Multiply each column of the block by a fixed matrix (a block must be 128 bits)

    01 02 03 04     -->       19  14  17  20
    05 06 07 08               47  42  45  48
    09 10 11 12               75  70  73  76
    13 14 15 16              103  98 101 104
    */

    u_int8_t initialBlock[16];
    memcpy(initialBlock, block, 16);

    for(int indexColumn = 0; indexColumn < 4; ++indexColumn) {
        for(int indexRow = 0; indexRow < 4; ++indexRow) {
            u_int8_t value = 0;
            for(int indexColumnVariant = 0; indexColumnVariant < 4; ++indexColumnVariant) {
                value ^= galois_multiplication(initialBlock[indexColumnVariant + (indexColumn * 4)], mixColumnsMatrix[indexRow][indexColumnVariant]);
            }
            block[indexRow + indexColumn * 4] = value;
        }
    }
}

const u_int8_t invMixColumnsMatrix[4][4] = {
        {0x0e, 0x0b, 0x0d, 0x09},
        {0x09, 0x0e, 0x0b, 0x0d},
        {0x0d, 0x09, 0x0e, 0x0b},
        {0x0b, 0x0d, 0x09, 0x0e}
};

void invMixColumns(u_int8_t* block) {
    /*

    Multiply each column of the block by a fixed matrix (a block must be 128 bits)

    01 02 03 04     -->       19  14  17  20
    05 06 07 08               47  42  45  48
    09 10 11 12               75  70  73  76
    13 14 15 16              103  98 101 104
    */

    u_int8_t initialBlock[16];
    memcpy(initialBlock, block, 16);

    for(int indexColumn = 0; indexColumn < 4; ++indexColumn) {
        for(int indexRow = 0; indexRow < 4; ++indexRow) {
            u_int8_t value = 0;
            for(int indexColumnVariant = 0; indexColumnVariant < 4; ++indexColumnVariant) {
                value ^= galois_multiplication(initialBlock[indexColumnVariant + (indexColumn * 4)], invMixColumnsMatrix[indexRow][indexColumnVariant]);
            }
            block[indexRow + indexColumn * 4] = value;
        }
    }
}

// ***********************
// AddRoundKey
// ***********************
Aes128KeyExpanded createExpandedKey(const Aes128Key firstKeyBlock) {
    Aes128KeyExpanded expandedKey = malloc(11 * sizeof(Aes128Key));
    for (int index = 0; index < 11; ++index) {
        expandedKey[index] = malloc(16 * sizeof(u_int8_t));
    }

    memcpy(expandedKey[0], firstKeyBlock, 16);

    return expandedKey;
}
void destroyExpandedKey(Aes128KeyExpanded expandedKey) {
    for (int index = 0; index < 11; ++index) {
        free(expandedKey[index]);
    }
    free(expandedKey);
}

Aes128KeyExpanded expandKey(Aes128Key baseKey, const int nbRounds) {
    Aes128KeyExpanded keyExpanded = createExpandedKey(baseKey);

    for(int indexRound = 1; indexRound <= nbRounds; ++indexRound) {
        Aes128Key key = keyExpanded[indexRound];
        Aes128Key previousKey = keyExpanded[indexRound - 1];

        for(int indexColumn = 0; indexColumn < 4; ++indexColumn) {
            if (indexColumn == 0) {
                u_int8_t tmp[4] = {0};
                for(int indexRow = 0; indexRow < 4; ++indexRow) {
                    // 1. Rotate the word
                    if (indexRow != 3) {
                        tmp[indexRow] = previousKey[12 + indexRow + 1];
                    } else {
                        tmp[indexRow] = previousKey[12];
                    }

                    // 2. SubBytes
                    tmp[indexRow] = getSubBytesValue(tmp[indexRow]);
                }

                tmp[0] = tmp[0] ^ getRconValue(indexRound);

                for(int indexRow = 0; indexRow < 4; ++indexRow) {
                    key[indexRow] = previousKey[indexRow] ^ tmp[indexRow];
                }
            } else {
                for(int indexRow = 0; indexRow < 4; ++indexRow) {
                    int indexInKey = indexRow + indexColumn * 4;

                    key[indexInKey] = previousKey[indexInKey] ^ key[indexInKey - 4];
                }
            }

        }
    }

    return keyExpanded;
}

void addRoundKey(Aes128Block block, const Aes128KeyExpanded completeKey, int indexRound) {
    Aes128Key key = completeKey[indexRound];

    for(int indexColumn = 0; indexColumn < 4; ++indexColumn) {
        for(int indexRow = 0; indexRow < 4; ++indexRow) {
            const int index = indexRow * 4 + indexColumn;
            block[index] = block[index] ^ key[index];
        }
    }
}

// ***********************
// Encryption & Decryption
// ***********************

void decrypt(u_int8_t* cipherText, u_int8_t* key, int cipherTextSize, int keySize) {
    if (keySize != KEY_SIZE) {
        return;
    }
    if (cipherTextSize != BLOCK_SIZE) {
        return;
    }

    // 1. Expand the key
    Aes128KeyExpanded expandedKey = expandKey(key, 10);

    // 2. AddRoundKey
    addRoundKey(cipherText, expandedKey, 10);

    // 2. Rounds
    for(int indexRound = 9; indexRound >= 0; --indexRound) {
        invShiftRows(cipherText);
        invSubBytes(cipherText);
        addRoundKey(cipherText, expandedKey, indexRound);
        if (indexRound != 0) {
            invMixColumns(cipherText);
        }
    }

    destroyExpandedKey(expandedKey);
}

void encrypt(Aes128Block plainText, Aes128Key key, int plainTextSize, int keySize) {
    if (keySize != KEY_SIZE) {
        return;
    }
    if (plainTextSize != BLOCK_SIZE) {
        return;
    }

    // 1. Expand the key
    Aes128KeyExpanded expandedKey = expandKey(key, 10);

    // 2. AddRoundKey
    addRoundKey(plainText, expandedKey, 0);

    // 3. Rounds
    for(int indexRound = 1; indexRound <= 10; ++indexRound) {
        subBytes(plainText);
        shiftRows(plainText);
        if (indexRound != 10) {
            mixColumns(plainText);
        }
        addRoundKey(plainText, expandedKey, indexRound);
    }

    destroyExpandedKey(expandedKey);
}

Aes128Block generateBlock() {
    Aes128Block block = malloc(BLOCK_SIZE);

    block[0] = 0x46;
    block[1] = 0x72;
    block[2] = 0x6f;
    block[3] = 0x6d;
    block[4] = 0x20;
    block[5] = 0x57;
    block[6] = 0x69;
    block[7] = 0x6b;
    block[8] = 0x69;
    block[9] = 0x70;
    block[10] = 0x65;
    block[11] = 0x64;
    block[12] = 0x69;
    block[13] = 0x61;
    block[14] = 0x2c;
    block[15] = 0x20;

    return block;
}
void destroyBlock(Aes128Block block) {
    free(block);
}

Aes128Key generateKey() {
    Aes128Key key = malloc(KEY_SIZE);

    key[0] = 0x2b;
    key[4] = 0x7e;
    key[8] = 0x15;
    key[12] = 0x16;

    key[1] = 0x28;
    key[5] = 0xae;
    key[9] = 0xd2;
    key[13] = 0xa6;

    key[2] = 0xab;
    key[6] = 0xf7;
    key[10] = 0x15;
    key[14] = 0x88;

    key[3] = 0x09;
    key[7] = 0xcf;
    key[11] = 0x4f;
    key[15] = 0x3c;

    return key;
}
void destroyKey(Aes128Key key) {
    free(key);
}


int main() {
    Aes128Block block = generateBlock();
    // Create a copy of the block
    Aes128Block initialBlock = generateBlock();
    memcpy(initialBlock, block, BLOCK_SIZE);

    Aes128Key key = generateKey();

    encrypt(block, key, BLOCK_SIZE, KEY_SIZE);
    printf("Encrypted block : \n");
    for(int index = 0; index < 16; ++index) {
        printf("%02x ", block[index]);
    }
    printf("\n\n");

    decrypt(block, key, BLOCK_SIZE, KEY_SIZE);
    printf("Decrypted block : \n");
    for(int index = 0; index < 16; ++index) {
        printf("%02x ", block[index]);
    }
    printf("\n\n");

    // Check that the block is the same as the initial block
    for(int index = 0; index < 16; ++index) {
        if (block[index] != initialBlock[index]) {
            printf("Error : block is not the same as the initial block\n");
            return 1;
        }
    }

    destroyBlock(block);
    destroyBlock(initialBlock);
    destroyKey(key);

    return 0;
}

/*
int main(int argc, char** argv) {
    if(argc != 4) {
        printf("Usage : ./aesEcb <input file> <output file> <mode>\n");
        return 1;
    }

    FILE* file = fopen(argv[1], "r");
    if(file == NULL) {
        printf("Error : cannot open file %s\n", argv[1]);
        return 1;
    }
    FILE* outputFile = fopen(argv[2], "w");

    fseek(file, 0, SEEK_END); // seek to end of file
    long fileSizeInByte = ftell(file); // get current file pointer
    fseek(file, 0, SEEK_SET); // seek back to beginning of file

    Aes128Key key = generateKey();

    if(strcmp(argv[3], "encrypt") == 0) {
        while(!feof(file)) {
            Aes128Block block = malloc(BLOCK_SIZE);
            int indexByte = 0;
            while(indexByte < BLOCK_SIZE && !feof(file)) {
                block[indexByte] = fgetc(file);
                ++indexByte;
            }
            encrypt(block, key, BLOCK_SIZE, KEY_SIZE);
            for(int indexByte = 0; indexByte < BLOCK_SIZE; ++indexByte) {
                fputc(block[indexByte], outputFile);
            }
        }
    } else if(strcmp(argv[3], "decrypt") == 0) {
        while(!feof(file)) {
            Aes128Block block = malloc(BLOCK_SIZE);
            int indexByte = 0;
            while(indexByte < BLOCK_SIZE && !feof(file)) {
                block[indexByte] = fgetc(file);
                ++indexByte;
            }
            decrypt(block, key, BLOCK_SIZE, KEY_SIZE);
            for(int indexByte = 0; indexByte < BLOCK_SIZE; ++indexByte) {
                fputc(block[indexByte], outputFile);
            }
        }
    }
    fclose(file);
    fclose(outputFile);
    destroyKey(key);
    return 0;
}
 */