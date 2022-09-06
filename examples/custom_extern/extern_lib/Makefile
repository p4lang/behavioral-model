LIBS = definition.so

CXX = g++
CXXFLAGS = -Wall -Wextra -g -O2 -fPIC
LDFLAGS = -shared

.PHONY: all clean

all: $(LIBS)

%.so: %.cpp
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $<

clean:
	rm -f $(LIBS)
