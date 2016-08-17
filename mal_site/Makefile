CXX = g++
CFLAGS = -o
LDFLAGS = -lpcap -lpthread
TARGET = mal_site
SOURCE = source.cpp

$(TARGET): $(SOURCE)
	$(CXX) $(CFLAGS) $@ $< $(LDFLAGS)

clean:
	rm $(TARGET)
