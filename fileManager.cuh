#ifndef FILE_MANAGER_H
#define FILE_MANAGER_H

#include <stdio.h>

class FileManager
{

public:
    FileManager(const char *fileName, const char *mode);
    ~FileManager();

    void readData(char *data, int size);
    void writeData(const char *data);
private:
    const char *fileName;
    FILE *fptr;
};

#endif