CC=$(CROSS_COMPILE)gcc
#STMCFLAGS = -mcpu=cortex-m4 -mthumb -mlittle-endian -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb-interwork -fsingle-precision-constant

CFLAGS=-Iinclude -Imodules -Wall -ggdb $(STMCFLAGS)
#CFLAGS=-Iinclude -Imodules -Wall -Os $(STMCFLAGS)

TEST_LDFLAGS=-lvdeplug -pthread  build/modules/*.o build/lib/*.o

PREFIX?=./build

.c.o:
	@echo "\t[CC] $<"
	@$(CC) -c $(CFLAGS) -o $@ $<

%.elf: %.o
	@echo "\t[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $< $(TEST_LDFLAGS)


CORE_OBJ= stack/pico_stack.o \
          stack/pico_arp.o \
          stack/pico_frame.o \
          stack/pico_device.o \
          stack/pico_protocol.o \
          stack/pico_socket.o


MOD_OBJ=  modules/pico_ipv4.o \
					modules/pico_icmp4.o \
					modules/pico_udp.o \
					modules/pico_tcp.o \
					modules/pico_nat.o \
					modules/pico_dev_loop.o

POSIX_OBJ=  modules/pico_dev_vde.o \
						modules/pico_dev_tun.o \
						modules/ptsocket/pico_ptsocket.o


TEST_ELF= test/vde_test.elf \
          test/testclient.elf \
          test/testserver.elf \
          test/vde_receiver.elf \
          test/vde_send.elf \
          test/echoclient.elf \
          test/sendclient.elf \
          test/echoclientUDP.elf \
          test/nat_send.elf       \
          test/nat_echo.elf       \
          test/nat_box.elf       \
          test/picoapp.elf        \
          test/ptsock_server.elf        \
          test/ptsock_client.elf        \
          test/testnat.elf

all: mod $(CORE_OBJ)
	@mkdir -p build/lib
	@mv stack/*.o build/lib

mod: $(MOD_OBJ)
	@mkdir -p build/modules
	@mv modules/*.o build/modules

posix: all $(POSIX_OBJ)
	@mv modules/*.o build/modules
	@mv modules/ptsocket/*.o build/modules

test: posix $(TEST_ELF)
	@mkdir -p build/test/
	@rm test/*.o
	@mv test/*.elf build/test

tst: test


lib: all mod
	@mkdir -p build/lib
	@mkdir -p build/include
	@cp -f include/*.h build/include
	@cp -fa include/arch build/include
	@cp -f modules/*.h build/include
	@echo "\t[AR] build/lib/picotcp.a"
	@$(CROSS_COMPILE)ar cru build/lib/picotcp.a build/modules/*.o build/lib/*.o
	@echo "\t[RANLIB] build/lib/picotcp.a"
	@$(CROSS_COMPILE)ranlib build/lib/picotcp.a

loop: all mod
	mkdir -p build/test
	@$(CC) -c -o build/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)
	@$(CC) -c -o build/loop_ping.o test/loop_ping.c $(CFLAGS) -ggdb


clean:
	@echo "\t[CLEAN] build/"
	@rm -rf build tags
