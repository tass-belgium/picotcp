CC=gcc
CFLAGS=-ggdb -I../build/include/ -L../build/lib/ -lpicotcp -lvdeplug
APPNAME=test_tftp_app_client

.PHONY: clean
all: test_tftp_app_client
test_tftp_app_client: test_tftp_app_client.o
	$(CC) -o test_tftp_app_client ../build/modules/pico_dev_vde.o $^ $(CFLAGS)
clean:
	rm -f ${APPNAME}.o
