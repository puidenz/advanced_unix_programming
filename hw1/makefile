CXX = g++
FLAG = -g -Wall -std=c++17 -O2

.PHONY: all clean install

all: hw1.o
	$(CXX) $^ -o hw1

%.o: %.cpp
	$(CXX) $^ $(FLAG) -c 

clean:
	rm *.o