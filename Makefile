CC = g++
CFLAGS = -g -pedantic
TARGET = ipk-sniffer
FILES = ipk-sniffer.cpp
all: $(TARGET)

$(TARGET): $(FILES)
	$(CC) $(CFLAGS) $(FILES) -lpcap -o $(TARGET)

clean:
	rm -f $(TARGET)