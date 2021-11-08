CC = g++

CFLAGS = -std=c++17 -pedantic
LDFLAGS = -lpcap -lssl -lcrypto

TARGET = secret

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CC) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

clean:
		$(RM) $(TARGET)

tar:
		tar -cvf xnorek01.tar Makefile secret.cpp secret.1