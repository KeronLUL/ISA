CXX = g++

CFLAGS = -std=c++17 -pedantic
LDFLAGS = -lpcap -lssl -lcrypto

TARGET = secret

all: $(TARGET)

$(TARGET): $(TARGET).cpp
			$(CXX) $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

merlin:
	$(CXX)-11.2 $(CFLAGS) $(TARGET).cpp -o $(TARGET) $(LDFLAGS)

clean:
		$(RM) $(TARGET)

tar:
		tar -cvf xnorek01.tar Makefile secret.cpp secret.1 manual.pdf