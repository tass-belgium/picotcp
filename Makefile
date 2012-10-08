all: protocol.c
	gcc -c protocol.c -Wall
	gcc -c pico_arp.c -Wall

clean:
	rm -f *.o
