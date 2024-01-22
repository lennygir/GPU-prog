#include <stdio.h>
#include <string.h>

#define BLOCK_SIZE 128
#define KEY_SIZE 128

/* 
========================
AES ECB Encryption
========================

Source : 
    - Operations : https://www.youtube.com/watch?v=O4xNJsjtN6E
    - Implementation : https://github.com/m3y54m/aes-in-c/blob/main/src/main.c#L452
    - AddRoundKey : https://en.wikipedia.org/wiki/AES_key_schedule

Operations in a round :
    1. XOR
    2. SubBytes : Substitude each byte with another byte according to a lookup table
    3. ShiftRows : Shift each row one by one (1st row by 0, 2nd row by 1, 3rd row by 2, 4th row by 3)
        1234 = 1234 (1st row)
        1234 = 2341 (2nd row)
        1234 = 3412 (3rd row)
        1234 = 4123 (4th row)
    4. MixColumns (not last round) : Each column is multiplied by a fixed matrix
    5. AddRoundKey

Number of rounds :
    10 for 128 bit key
    12 for 192 bit key
    14 for 256 bit key

*/

// ***********************
// SubBytes
// ***********************

// ***********************
// ShiftRows
// ***********************

void shiftRows(char* block) {
    /*

    Shift each line of the block from right to left (a block must be 128 bits)

    01 02 03 04     -->     02 03 04 01
    05 06 07 08             06 07 08 05
    09 10 11 12             12 09 10 11
    13 14 15 16             16 13 14 15
    */

    for(int rowIndex = 0; rowIndex < 4; ++rowIndex) {
        const int tmp = block[(rowIndex * 4)];
        for(int columnIndex = 0; columnIndex < 3; ++columnIndex) {
            block[(rowIndex * 4) + columnIndex] = block[(rowIndex * 4) + columnIndex + 1];
        }
        block[(rowIndex * 4) + 3] = tmp;
    }
}

void invShiftRows(char* block) {
    /*

    Shift each line of the block from left to right (a block must be 128 bits)

    01 02 03 04     -->     04 01 02 03
    05 06 07 08             08 05 06 07
    09 10 11 12             12 09 10 11
    13 14 15 16             16 13 14 15
    */

    for(int rowIndex = 0; rowIndex < 4; ++rowIndex) {
        const int tmp = block[(rowIndex * 4) + 3];
        for(int columnIndex = 3; columnIndex > 0; --columnIndex) {
            block[(rowIndex * 4) + columnIndex] = block[(rowIndex * 4) + columnIndex - 1];
        }
        block[(rowIndex * 4)] = tmp;
    }
}

// ***********************
// MixColumns
// ***********************

const int mixColumnsMatrix[4][4] = {
    {0x02, 0x03, 0x01, 0x01},
    {0x01, 0x02, 0x03, 0x01},
    {0x01, 0x01, 0x02, 0x03},
    {0x03, 0x01, 0x01, 0x02}
};

void mixColumns(char* block) {
    /*

    Multiply each column of the block by a fixed matrix (a block must be 128 bits)

    01 02 03 04     -->       19  14  17  20
    05 06 07 08               47  42  45  48
    09 10 11 12               75  70  73  76
    13 14 15 16              103  98 101 104
    */

    char initialBlock[16];
    strcpy(initialBlock, block);

    for(int indexColumn = 0; indexColumn < 4; ++indexColumn) {
        for(int indexRow = 0; indexRow < 4; ++indexRow) {
            int value = 0;
            for(int indexColumnVariant = 0; indexColumnVariant < 4; ++indexColumnVariant) {
                value += initialBlock[(indexRow * 4) + indexColumnVariant] * mixColumnsMatrix[indexColumnVariant][indexColumn];
            }
            block[indexRow * 4 + indexColumn] = value;
        }
    }
}

char* decrypt(char* cipherText, char* key, int cipherTextSize, int keySize) {
    return;
}

char* encrypt(char* plainText, char* key, int plainTextSize, int keySize) {
    return;
}

