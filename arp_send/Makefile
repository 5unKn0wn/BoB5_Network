CXX = g++
CFLAGS = -o
LDFLAGS = -lpcap
TARGET = arp_send
SOURCE = source.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CFLAGS) $@ $< $(LDFLAGS)

clean:
	rm $(TARGET)
