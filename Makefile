CC = g++

CFLAGS = -std=c++17 -pedantic -Wall -Wextra
LDFLAGS = -lpcap -lssl -lcrypto

TARGET = secret

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

clean:
		$(RM) $(TARGET)