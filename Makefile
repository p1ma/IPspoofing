# Compile
CC = g++

# Flags
FLAGS= -std=c++11 -Wall -g -o

# Actions
all: main.cpp
	$(CC) $(FLAGS) spoof main.cpp
clean:
	rm -f *.o spoof *~

