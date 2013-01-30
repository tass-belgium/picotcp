CC=$(CROSS_COMPILE)gcc
TEST_LDFLAGS=-pthread  $(PREFIX)/modules/*.o $(PREFIX)/lib/*.o -lvdeplug

PREFIX?=./build
DEBUG?=1
DEBUG_IGMP2?=1
TCP?=1
UDP?=1
IPV4?=1
NAT?=1
ICMP4?=1
MCAST?=1
DEVLOOP?=1
PING?=1
DHCP_CLIENT?=1
DNS_CLIENT?=1
ENDIAN=little


ifeq ($(DEBUG),1)
CFLAGS=-Iinclude -Imodules -Wall -ggdb
  ifeq ($(DEBUG_IGMP2),1)
    OPTIONS+=-DPICO_UNIT_TEST_IGMP2
  endif
else
  CFLAGS=-Iinclude -Imodules -Wall -Os
endif

ifneq ($(ENDIAN),little)
  CFLAGS+=-DPICO_BIGENDIAN
endif

ifeq ($(ARCH),stm32)
  CFLAGS+=-mcpu=cortex-m4 \
  -mthumb -mlittle-endian -mfpu=fpv4-sp-d16 \
  -mfloat-abi=hard -mthumb-interwork -fsingle-precision-constant \
  -DSTM32
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
ifneq ($(TCP),0)
  include rules/tcp.mk
endif
ifneq ($(UDP),0)
  include rules/udp.mk
else
  MCAST=0
endif
ifneq ($(MCAST),0)
  include rules/mcast.mk
  include rules/igmp2.mk
endif
ifneq ($(NAT),0)
  include rules/nat.mk
endif
ifneq ($(DEVLOOP),0)
  include rules/devloop.mk
endif
ifneq ($(DHCP_CLIENT),0)
  include rules/dhcp_client.mk
endif
ifneq ($(DNS_CLIENT),0)
  include rules/dns_client.mk
endif

all: mod core lib

core: $(CORE_OBJ)
	@mkdir -p $(PREFIX)/lib
	@mv stack/*.o $(PREFIX)/lib

mod: $(MOD_OBJ)
	@mkdir -p $(PREFIX)/modules
	@mv modules/*.o $(PREFIX)/modules

posix: all $(POSIX_OBJ)
	@mv modules/*.o $(PREFIX)/modules
	@mv modules/ptsocket/*.o $(PREFIX)/modules


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
          test/testigmp2.elf   \
          test/dhcp_example.elf

test: posix $(TEST_ELF)
	@mkdir -p $(PREFIX)/test/
	@rm test/*.o
	@mv test/*.elf $(PREFIX)/test

tst: test

tstigmp2: posix test/testigmp2.elf 
	@mkdir -p $(PREFIX)/test/
	@rm test/*.o
	@mv test/*.elf $(PREFIX)/test


lib: mod core
	@mkdir -p $(PREFIX)/lib
	@mkdir -p $(PREFIX)/include
	@cp -f include/*.h $(PREFIX)/include
	@cp -fa include/arch $(PREFIX)/include
	@cp -f modules/*.h $(PREFIX)/include
	@echo "\t[AR] $(PREFIX)/lib/picotcp.a"
	@$(CROSS_COMPILE)ar cru $(PREFIX)/lib/picotcp.a $(PREFIX)/modules/*.o $(PREFIX)/lib/*.o
	@echo "\t[RANLIB] $(PREFIX)/lib/picotcp.a"
	@$(CROSS_COMPILE)ranlib $(PREFIX)/lib/picotcp.a

loop: mod core
	mkdir -p $(PREFIX)/test
	@$(CC) -c -o $(PREFIX)/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)
	@$(CC) -c -o $(PREFIX)/loop_ping.o test/loop_ping.c $(CFLAGS) -ggdb


clean:
	@echo "\t[CLEAN] $(PREFIX)/"
	@rm -rf $(PREFIX) tags
