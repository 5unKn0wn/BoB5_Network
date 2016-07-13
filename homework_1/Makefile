CXX = g++
CFLAGS = -o
LDFLAGS = -lpcap
TARGET = homework1
SOURCE = source.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CFLAGS) $@ $< $(LDFLAGS)

clean:
	rm $(TARGET)
