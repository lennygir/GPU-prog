#include "fileManager.cuh"

FileManager::FileManager(const char *fileName, const char *mode) : fileName(fileName)
{
    fptr = fopen(fileName, mode);
    if (fptr == nullptr) {
        printf("Error opening file: %s", fileName);
    }
}

FileManager::~FileManager()
{
    if (fptr != nullptr) {
        fclose(fptr);
    }
}

void FileManager::readData(char *data, int size) {
    fgets(data, size, this->fptr);
}

void FileManager::writeData(const char *data) {
    int result = fputs(data, this->fptr);
    if (result == EOF) {
        printf("Error writing to file: %s\n", fileName);
    }
}