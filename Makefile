CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld
AR:=$(CROSS_COMPILE)ar
RANLIB:=$(CROSS_COMPILE)ranlib
STRIP_BIN:=$(CROSS_COMPILE)strip
TEST_LDFLAGS=-pthread  $(PREFIX)/modules/*.o $(PREFIX)/lib/*.o -lvdeplug -lpcap
LIBNAME:="libpicotcp.a"

PREFIX?=./build
DEBUG?=1
ENDIAN?=little
STRIP?=0
RTOS?=0

# Default compiled-in protocols
TCP?=1
UDP?=1
IPV4?=1
IPFRAG?=1
NAT?=1
ICMP4?=1
MCAST?=1
DEVLOOP?=1
PING?=1
DHCP_CLIENT?=1
DHCP_SERVER?=1
DNS_CLIENT?=1
IPFILTER?=1
CRC?=0
HTTP_CLIENT?=1
HTTP_SERVER?=1
ZMQ?=1
OLSR?=1
SLAACV4?=1

CFLAGS=-Iinclude -Imodules -Wall -Wdeclaration-after-statement -W -Wextra -Wshadow -Wcast-qual -Wwrite-strings -Wmissing-field-initializers
# extra flags recommanded by TIOBE TICS framework to score an A on compiler warnings
CFLAGS+= -Wconversion 
# request from Toon
CFLAGS+= -Wcast-align

ifeq ($(DEBUG),1)
  CFLAGS+=-ggdb
else
  CFLAGS+=-Os
endif

ifneq ($(ENDIAN),little)
  CFLAGS+=-DPICO_BIGENDIAN
endif

ifneq ($(RTOS),0)
  CFLAGS+=-DPICO_SUPPORT_RTOS
endif

ifeq ($(ARCH),stm32)
  CFLAGS+=-mcpu=cortex-m4 \
  -mthumb -mlittle-endian -mfpu=fpv4-sp-d16 \
  -mfloat-abi=hard -mthumb-interwork -fsingle-precision-constant \
  -DSTM32
endif

ifeq ($(ARCH),stm32-softfloat)
  CFLAGS+=-mcpu=cortex-m3 \
  -mthumb -mlittle-endian \
  -mfloat-abi=soft -mthumb-interwork \
  -DSTM32
endif

ifeq ($(ARCH),msp430)
  CFLAGS+=-DMSP430
endif

ifeq ($(ARCH),stellaris)
  CFLAGS+=-mthumb -DSTELLARIS
endif

ifeq ($(ARCH),lpc)
  CFLAGS+=-O0 -g3 -fmessage-length=0 -fno-builtin \
  -ffunction-sections -fdata-sections -mlittle-endian \
  -mcpu=cortex-m3 -mthumb -MMD -MP -DLPC
endif


ifeq ($(ARCH),pic24)
  CFLAGS+=-DPIC24 -c -mcpu=24FJ256GA106  -MMD -MF -g -omf=elf \
  -mlarge-code -mlarge-data -O0 -msmart-io=1 -msfr-warn=off
endif

.c.o:
	@echo -e "\t[CC] $<"
	@$(CC) -c $(CFLAGS) -o $@ $<

%.elf: %.o
	@echo -e "\t[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $< $(TEST_LDFLAGS)

CFLAGS+=$(OPTIONS)


CORE_OBJ= stack/pico_stack.o \
          stack/pico_arp.o \
          stack/pico_frame.o \
          stack/pico_device.o \
          stack/pico_protocol.o \
          stack/pico_socket.o \
	  stack/pico_tree.o

POSIX_OBJ=  modules/pico_dev_vde.o \
						modules/pico_dev_tun.o \
						modules/pico_dev_mock.o \
            modules/pico_dev_pcap.o \
						modules/ptsocket/pico_ptsocket.o


ifneq ($(IPV4),0)
  include rules/ipv4.mk
endif
ifneq ($(IPFRAG),0)
  include rules/ipfrag.mk
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
  include rules/igmp.mk
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
ifneq ($(DHCP_SERVER),0)
  include rules/dhcp_server.mk
endif
ifneq ($(DNS_CLIENT),0)
  include rules/dns_client.mk
endif
ifneq ($(SIMPLE_HTTP),0)
  include rules/http.mk
endif
ifneq ($(IPFILTER),0)
  include rules/ipfilter.mk
endif
ifneq ($(CRC),0)
  include rules/crc.mk
endif
ifneq ($(HTTP_SERVER),0)
  include rules/httpServer.mk
endif
ifneq ($(HTTP_CLIENT),0)
  include rules/httpClient.mk
endif
ifneq ($(ZMQ),0)
  include rules/zmq.mk
endif
ifneq ($(OLSR),0)
  include rules/olsr.mk
endif
ifneq ($(SLAACV4),0)
  include rules/slaacv4.mk
endif

all: mod core lib

core: $(CORE_OBJ)
	@mkdir -p $(PREFIX)/lib
	@mv stack/*.o $(PREFIX)/lib

mod: $(MOD_OBJ)
	@mkdir -p $(PREFIX)/modules
	@mv modules/*.o $(PREFIX)/modules || echo

posix: all $(POSIX_OBJ)
	@mv modules/*.o $(PREFIX)/modules || echo
	@mv modules/ptsocket/*.o $(PREFIX)/modules || echo


TEST_ELF= test/picoapp.elf

test: posix $(TEST_ELF)
	@mkdir -p $(PREFIX)/test/
	@rm test/*.o
	@mv test/*.elf $(PREFIX)/test

tst: test

lib: mod core
	@mkdir -p $(PREFIX)/lib
	@mkdir -p $(PREFIX)/include
	@cp -f include/*.h $(PREFIX)/include
	@cp -fa include/arch $(PREFIX)/include
	@cp -f modules/*.h $(PREFIX)/include
	@echo -e "\t[AR] $(PREFIX)/lib/$(LIBNAME)"
	@$(AR) cru $(PREFIX)/lib/$(LIBNAME) $(PREFIX)/modules/*.o $(PREFIX)/lib/*.o \
	  || $(AR) cru $(PREFIX)/lib/$(LIBNAME) $(PREFIX)/lib/*.o 
	@echo -e "\t[RANLIB] $(PREFIX)/lib/$(LIBNAME)"
	@$(RANLIB) $(PREFIX)/lib/$(LIBNAME)
	@test $(STRIP) -eq 1 && (echo -e "\t[STRIP] $(PREFIX)/lib/$(LIBNAME)" \
     && $(STRIP_BIN) $(PREFIX)/lib/$(LIBNAME)) \
     || echo -e "\t[KEEP SYMBOLS] $(PREFIX)/lib/$(LIBNAME)" 
	@echo -e "\t[LIBSIZE] `du -b $(PREFIX)/lib/$(LIBNAME)`"
loop: mod core
	mkdir -p $(PREFIX)/test
	@$(CC) -c -o $(PREFIX)/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)
	@$(CC) -c -o $(PREFIX)/loop_ping.o test/loop_ping.c $(CFLAGS) -ggdb

units: mod core lib
	@echo -e "\n\t[UNIT TESTS SUITE]"
	@mkdir -p $(PREFIX)/test
	@echo -e "\t[CC] units.o"
	@$(CC) -c -o $(PREFIX)/test/units.o test/units.c $(CFLAGS) -I stack -I modules -I includes -I test/unit
	@echo -e "\t[LD] $(PREFIX)/test/units"
	@$(CC) -o $(PREFIX)/test/units $(CFLAGS) $(PREFIX)/test/units.o -lcheck -lm -pthread -lrt

devunits: mod core lib
	@echo -e "\n\t[UNIT TESTS SUITE: device drivers]"
	@mkdir -p $(PREFIX)/test/unit/device/
	@echo -e "\t[CC] picotcp_mock.o"
	@$(CC) -c -o $(PREFIX)/test/unit/device/picotcp_mock.o $(CFLAGS) -I stack -I modules -I includes -I test/unit test/unit/device/picotcp_mock.c
	@$(CC) -c -o $(PREFIX)/test/unit/device/unit_dev_vde.o $(CFLAGS) -I stack -I modules -I includes -I test/unit test/unit/device/unit_dev_vde.c
	@echo -e "\t[LD] $(PREFIX)/test/devunits"
	@$(CC) -o $(PREFIX)/test/devunits $(CFLAGS) $(PREFIX)/test/unit/device/*.o -lcheck -lm -pthread -lrt


clean:
	@echo -e "\t[CLEAN] $(PREFIX)/"
	@rm -rf $(PREFIX) tags

mbed:
	@echo -e "\t[Creating PicoTCP.zip]"
	@rm -f PicoTCP.zip
	@cp include/pico_socket.h include/socket.tmp
	@echo "#define MBED\n" > include/mbed.tmp
	@cat include/mbed.tmp include/socket.tmp > include/pico_socket.h
	@zip -0 PicoTCP.zip -r include modules stack -x include/arch/ include/arch/* include/pico_config.h include/*.tmp modules/ptsocket/* modules/ptsocket/ modules/ptsocket/test/ modules/ptsocket/test/* modules/pico_dev_*
	@rm include/pico_socket.h include/mbed.tmp
	@mv include/socket.tmp include/pico_socket.h


style:
	@find . -iname "*.[c|h]" |xargs -x uncrustify --replace -l C -c uncrustify.cfg || true
	@find . -iname "*unc-backup*" |xargs -x rm || true

dummy: mod core lib
	@echo testing configuration...
	@$(CC) -c -o test/dummy.o test/dummy.c $(CFLAGS)
	@$(CC) -o dummy test/dummy.o $(PREFIX)/lib/libpicotcp.a $(LDFLAGS)
	@echo done.
	@rm -f test/dummy.o dummy 
