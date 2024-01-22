/*
====================
ECB
====================

Test :

- ShiftRows

int main() {
    char block[] = "Hello world !:)";
    shiftRows(block);
    printf("%s\n", block);
    invShiftRows(block);
    printf("%s\n", block);
    return 0;
}

- mixColumns

int main() {
    char block[16] = {1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16};
    mixColumns(block);
    for(int i = 0; i < 16; ++i) {
        printf("%d ", block[i]);
    }
    return 0;
}

*/