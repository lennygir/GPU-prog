#include <stdio.h>
#include "fileManager.cuh"

int main() {
    // Your CUDA code here
    printf("Hello World from Cuda Code!\n");

    FileManager fileManager("testData.txt", "r+");
    char *data = (char*)malloc(10 * sizeof(char));

    fileManager.readData(data, 10);
    for(int i = 0; i < 10; ++i) {
        printf("%c", data[i]);
    }

    fileManager.readData(data, 10);
    for(int i = 0; i < 10; ++i) {
        printf("%c", data[i]);
    }

    fileManager.writeData("Salut a tous :)");

    return 0;
}