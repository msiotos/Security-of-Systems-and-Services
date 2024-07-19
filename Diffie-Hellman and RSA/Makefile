# Makefile

# Compiler
CC = gcc
DBUG = -g
# Compiler flags

LDFLAGS = -lgmp

# Source files
SRCS = rsa_assign_1.c dh_assign_1.c

# Object files
OBJS = rsa_assign_1.o dh_assign_1.o

# Executable
TARGET = rsa_assign_1, dh_assign_1

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c -o $@ $<

clean:
	rm -f $(TARGET) $(OBJS)



