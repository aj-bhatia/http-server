#------------------------------------------------------------------------------
# Bhatia, Ajay
# ajbhatia
# asgn0
# Makefile
#------------------------------------------------------------------------------

CC = clang
CFLAGS = -Wall -Wpedantic -Werror -Wextra

all: httpserver

httpserver: httpserver.o
	$(CC) -o httpserver httpserver.o

httpserver.o: httpserver.c
	$(CC) $(CFLAGS) -c httpserver.c
		
checkServer:
	valgrind --leak-check=full ./httpserver -l valfile 1234
	
clean:
	rm -f httpserver httpserver.o
	
format:
	clang-format -i -style=file httpserver.c
