# GPU Programming - Encryption and Decryption algorithms

## Description

## Algorithms

### AES

#### ECB

##### Naive implementation

##### Kernel in kernel implementation

In this implementation we will try to calculate each byte of an AES block in a different thread. This will be done by using a kernel in kernel approach. The outer kernel will be responsible for the AES block and the inner kernel will be responsible for the AES byte.

To compile the code we need specific options :
- arch=compute_35 : specify the compute architecture we want to compile for
- rdc=true : allow separate compilation mode


```bash
nvcc -arch=compute_35 -rdc=true aes.cu
```

