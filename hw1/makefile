CXX = g++
FLAG = -g -Wall

.PHONY: all clean install

all: hw1.o
	$(CXX) $(FLAG) -o hw1 $^

%.o: %.cpp
	$(CXX) -c $^

clean:
	rm *.o