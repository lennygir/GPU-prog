# Compiler
NVCC := nvcc
# Compiler flags
NVCCFLAGS := -std=c++11

# Source files
SRCS := $(wildcard *.cu)
OBJS := $(SRCS:.cu=.o)

# Target executable
TARGET := main

# Compilation rule
%.o: %.cu
	$(NVCC) $(NVCCFLAGS) -c $< -o $@

# Linking rule
$(TARGET): $(OBJS)
	$(NVCC) $(NVCCFLAGS) $^ -o $@

.PHONY: all clean

all: $(TARGET)

clean:
	rm -f $(OBJS) $(TARGET)
