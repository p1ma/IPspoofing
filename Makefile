# Compile
CC = g++

# Flags
FLAGS= -std=c++11 -Wall -g -o
ENDFLAGS = -lpcap

# Actions
all: main.cpp
	$(CC) $(FLAGS) spoof main.cpp $(ENDFLAGS)
clean:
	rm -f *.o spoof *~

