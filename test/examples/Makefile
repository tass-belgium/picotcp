all: test.elf

test_http.o: test_http.c
	gcc -c  test_http.c -I../../include -I../../modules -Os

../../build/lib/picotcp.a:
	make -C ../.. test

test.elf: test_http.o ../../build/lib/picotcp.a
	gcc -o test.elf test_http.o ../../build/lib/picotcp.a -lvdeplug
	strip test.elf

clean:
	rm -rf *.o *.elf
