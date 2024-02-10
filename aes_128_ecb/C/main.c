#include <stdio.h>

#include "aes_core.c"

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage : ./main <encrypt | decrypt> <input file> <output file> <key>\n");
        return 1;
    }

    clock_t t; 

    FILE* file = fopen(argv[2], "r");
    if(file == NULL) {
        printf("Error : cannot open file %s\n", argv[1]);
        return 1;
    }
    FILE* outputFile = fopen(argv[3], "w");

    fseek(file, 0, SEEK_END); // seek to end of file
    long fileSizeInByte = ftell(file); // get current file pointer
    fseek(file, 0, SEEK_SET); // seek back to beginning of file

    Aes128Key key = generateKey(argv[4], KEY_SIZE);

    if(strcmp(argv[1], "encrypt") == 0) {
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
    } else if(strcmp(argv[1], "decrypt") == 0) {
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

    t = clock() - t;

    printf("Time taken : %fms\n", ((double)t)/CLOCKS_PER_SEC*1000);

    fclose(file);
    fclose(outputFile);
    destroyKey(key);
    return 0;
}