CXX = g++
CFLAGS = -o
LDFLAGS = -lpcap -lpthread
TARGET = arp_send
SOURCE = source.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CFLAGS) $@ $< $(LDFLAGS)

clean:
	rm $(TARGET)
