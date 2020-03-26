CXX = g++
FLAG = -g -Wall -std=c++14

.PHONY: all clean install

all: hw1.o
	$(CXX) $^ $(FLAG) -o hw1 

%.o: %.cpp
	$(CXX) $^ $(FLAG) -c 

clean:
	rm *.o