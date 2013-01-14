CC=$(CROSS_COMPILE)gcc
#STMCFLAGS = -mcpu=cortex-m4 -mthumb -mlittle-endian -mfpu=fpv4-sp-d16 -mfloat-abi=hard -mthumb-interwork -fsingle-precision-constant
TEST_LDFLAGS=-pthread  build/modules/*.o build/lib/*.o -lvdeplug

PREFIX?=./build
DEBUG?=1
DEBUG_IGMP2?=1
TCP?=1
UDP?=1
IPV4?=1
NAT?=1
ICMP4?=1
IGMP2?=1
DEVLOOP?=1
PING?=1
ENDIAN=little

ifeq ($(DEBUG),1)
CFLAGS=-Iinclude -Imodules -Wall -ggdb $(STMCFLAGS)
  ifeq ($(DEBUG_IGMP2),1)
    OPTIONS+=-DPICO_UNIT_TEST_IGMP2
  endif
else
  CFLAGS=-Iinclude -Imodules -Wall -Os $(STMCFLAGS)
endif

ifneq ($(ENDIAN),little)
  CFLAGS+=-DPICO_BIGENDIAN
endif

.c.o:
	@echo "\t[CC] $<"
	@$(CC) -c $(CFLAGS) -o $@ $<

%.elf: %.o
	@echo "\t[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $< $(TEST_LDFLAGS)

CFLAGS+=$(OPTIONS)


CORE_OBJ= stack/pico_stack.o \
          stack/pico_arp.o \
          stack/pico_frame.o \
          stack/pico_device.o \
          stack/pico_protocol.o \
          stack/pico_socket.o

POSIX_OBJ=  modules/pico_dev_vde.o \
						modules/pico_dev_tun.o \
						modules/ptsocket/pico_ptsocket.o


ifneq ($(IPV4),0)
  include rules/ipv4.mk
endif
ifneq ($(ICMP4),0)
  include rules/icmp4.mk
endif
ifneq ($(IGMP2),0)
  include rules/igmp2.mk
endif
ifneq ($(TCP),0)
  include rules/tcp.mk
endif
ifneq ($(UDP),0)
  include rules/udp.mk
endif
ifneq ($(NAT),0)
  include rules/nat.mk
endif
ifneq ($(DEVLOOP),0)
  include rules/devloop.mk
endif

all: mod core lib

core: $(CORE_OBJ)
	@mkdir -p build/lib
	@mv stack/*.o build/lib

mod: $(MOD_OBJ)
	@mkdir -p build/modules
	@mv modules/*.o build/modules

posix: all $(POSIX_OBJ)
	@mv modules/*.o build/modules
	@mv modules/ptsocket/*.o build/modules


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
          test/testnat.elf   \
          test/testigmp2.elf

test: posix $(TEST_ELF)
	@mkdir -p build/test/
	@rm test/*.o
	@mv test/*.elf build/test

tst: test

tstigmp2: posix test/testigmp2.elf 
	@mkdir -p build/test/
	@rm test/*.o
	@mv test/*.elf build/test


lib: mod core
	@mkdir -p build/lib
	@mkdir -p build/include
	@cp -f include/*.h build/include
	@cp -fa include/arch build/include
	@cp -f modules/*.h build/include
	@echo "\t[AR] build/lib/picotcp.a"
	@$(CROSS_COMPILE)ar cru build/lib/picotcp.a build/modules/*.o build/lib/*.o
	@echo "\t[RANLIB] build/lib/picotcp.a"
	@$(CROSS_COMPILE)ranlib build/lib/picotcp.a

loop: mod core
	mkdir -p build/test
	@$(CC) -c -o build/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)
	@$(CC) -c -o build/loop_ping.o test/loop_ping.c $(CFLAGS) -ggdb


clean:
	@echo "\t[CLEAN] build/"
	@rm -rf build tags
