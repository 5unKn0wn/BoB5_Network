CXX = g++
CFLAGS = -o
LDFLAGS = -lpcap
TARGET = pcap_test
SOURCE = source.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CFLAGS) $@ $< $(LDFLAGS)

clean:
	rm $(TARGET)
