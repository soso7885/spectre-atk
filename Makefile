SRC = spectre.c
CC = gcc
CFLAGS += -std=c99

TARGET = spectre
     
all: $(TARGET)

spectre: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)
     
clean:
	rm -f $(TARGET)
