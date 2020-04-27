# set the compiler
CC=gcc

# set compiler flags
CFLAGS=-o

#set dependencies for the program

program:
	$(CC) -g server.c $(CFLAGS) server
	$(CC) -g client.c $(CFLAGS) client
	$(CC) -g relay.c $(CFLAGS) relay

clean:
	rm -rf server client relay *.o *.out