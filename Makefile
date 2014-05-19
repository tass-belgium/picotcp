CC:=$(CROSS_COMPILE)gcc
LD:=$(CROSS_COMPILE)ld
AR:=$(CROSS_COMPILE)ar
RANLIB:=$(CROSS_COMPILE)ranlib
SIZE:=$(CROSS_COMPILE)size
STRIP_BIN:=$(CROSS_COMPILE)strip
TEST_LDFLAGS=-pthread  $(PREFIX)/modules/*.o $(PREFIX)/lib/*.o -lvdeplug -lpcap
LIBNAME:="libpicotcp.a"

PREFIX?=./build
DEBUG?=1
PROFILE?=0
PERF?=0
ENDIAN?=little
STRIP?=0
RTOS?=0

# Default compiled-in protocols
TCP?=1
UDP?=1
ETH?=1
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
MDNS?=1
SNTP_CLIENT?=1
IPFILTER?=1
CRC?=1
OLSR?=1
SLAACV4?=1
MEMORY_MANAGER?=0
MEMORY_MANAGER_PROFILING?=0

#IPv6 related
IPV6?=1

CFLAGS=-I$(PREFIX)/include -Iinclude -Imodules -Wall -Wdeclaration-after-statement -W -Wextra -Wshadow -Wcast-qual -Wwrite-strings -Wmissing-field-initializers $(EXTRA_CFLAGS)
# extra flags recommanded by TIOBE TICS framework to score an A on compiler warnings
CFLAGS+= -Wconversion
# request from Toon
CFLAGS+= -Wcast-align

ifeq ($(DEBUG),1)
  CFLAGS+=-ggdb
else
    ifeq ($(PERF), 1)
        CFLAGS+=-O3
    else
        CFLAGS+=-Os
    endif
endif

ifeq ($(PROFILE),1)
  CFLAGS+=-pg
endif


ifneq ($(ENDIAN),little)
  CFLAGS+=-DPICO_BIGENDIAN
endif

ifneq ($(RTOS),0)
  CFLAGS+=-DPICO_SUPPORT_RTOS
  OPTIONS+=-DPICO_SUPPORT_RTOS
endif

ifeq ($(ARCH),stm32)
  CFLAGS+=-mcpu=cortex-m4 \
  -mthumb -mlittle-endian -mfpu=fpv4-sp-d16 \
  -mfloat-abi=hard -mthumb-interwork -fsingle-precision-constant -DSTM32
endif

ifeq ($(ARCH),stm32_gc)
  CFLAGS_CORTEX_M4 = -mthumb -mtune=cortex-m4 -mcpu=cortex-m4 -mfpu=fpv4-sp-d16 
  CFLAGS_CORTEX_M4 += -mfloat-abi=hard -fsingle-precision-constant -Wdouble-promotion
  CFLAGS+= $(CFLAGS_CORTEX_M4) -mlittle-endian -DSTM32_GC
endif

ifeq ($(ARCH),faulty)
  CFLAGS+=-DFAULTY
  UNITS_OBJ+=test/pico_faulty.o
  TEST_OBJ+=test/pico_faulty.o
  DUMMY_EXTRA+=test/pico_faulty.o
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
  CFLAGS+=-fmessage-length=0 -fno-builtin \
  -ffunction-sections -fdata-sections -mlittle-endian \
  -mcpu=cortex-m3 -mthumb -MMD -MP -DLPC
endif

ifeq ($(ARCH),lpc18xx)
  CFLAGS+=-fmessage-length=0 -fno-builtin \
  -ffunction-sections -fdata-sections -mlittle-endian \
  -mcpu=cortex-m3 -mthumb -MMD -MP -DLPC18XX
endif

ifeq ($(ARCH),lpc43xx)
  CFLAGS+=-fmessage-length=0 -fno-builtin \
  -ffunction-sections -fdata-sections -mlittle-endian \
  -mcpu=cortex-m4 -mfloat-abi=hard -mfpu=fpv4-sp-d16  \
  -fsingle-precision-constant -mthumb -MMD -MP -DLPC43XX
endif

ifeq ($(ARCH),pic24)
  CFLAGS+=-DPIC24 -c -mcpu=24FJ256GA106  -MMD -MF -g -omf=elf \
  -mlarge-code -mlarge-data -msmart-io=1 -msfr-warn=off
endif

ifeq ($(ARCH),avr)
  CFLAGS+=-Wall -mmcu=$(MCU) -DAVR
endif

ifeq ($(ARCH),str9)
  CFLAGS+=-DSTR9 -mcpu=arm9e -march=armv5te -gdwarf-2 -Wall -marm -mthumb-interwork -fpack-struct
endif

ifeq ($(ARCH),none)
  CFLAGS+=-DARCHNONE
endif

.c.o:
	$(CC) -c $(CFLAGS) -o $@ $<

%.elf: %.o $(TEST_OBJ)
	@echo -e "\t[LD] $@"
	@$(CC) $(CFLAGS) -o $@ $< $(TEST_LDFLAGS) $(TEST_OBJ)


CORE_OBJ= stack/pico_stack.o \
          stack/pico_frame.o \
          stack/pico_device.o \
          stack/pico_protocol.o \
          stack/pico_socket.o \
		  stack/pico_socket_multicast.o \
			stack/pico_tree.o

POSIX_OBJ+=  modules/pico_dev_vde.o \
						modules/pico_dev_tun.o \
						modules/pico_dev_mock.o \
            modules/pico_dev_pcap.o \
						modules/ptsocket/pico_ptsocket.o

ifneq ($(ETH),0)
  include rules/eth.mk
endif
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
ifneq ($(MDNS),0)
  include rules/mdns.mk
endif
ifneq ($(IPFILTER),0)
  include rules/ipfilter.mk
endif
ifneq ($(CRC),0)
  include rules/crc.mk
endif
ifneq ($(OLSR),0)
  include rules/olsr.mk
endif
ifneq ($(SLAACV4),0)
  include rules/slaacv4.mk
endif
ifneq ($(IPV6),0)
  include rules/ipv6.mk
endif
ifneq ($(MEMORY_MANAGER),0)
  include rules/memory_manager.mk
endif
ifneq ($(MEMORY_MANAGER_PROFILING),0)
  OPTIONS+=-DPICO_SUPPORT_MM_PROFILING
endif
ifneq ($(SNTP_CLIENT),0)
  include rules/sntp_client.mk
endif
all: mod core lib

core: deps $(CORE_OBJ)
	@mkdir -p $(PREFIX)/lib
	@mv stack/*.o $(PREFIX)/lib

mod: deps $(MOD_OBJ)
	@mkdir -p $(PREFIX)/modules
	@mv modules/*.o $(PREFIX)/modules || echo

posix: all $(POSIX_OBJ)
	@mv modules/*.o $(PREFIX)/modules || echo
	@mv modules/ptsocket/*.o $(PREFIX)/modules || echo


TEST_ELF= test/picoapp.elf
TEST6_ELF= test/picoapp6.elf

test: posix $(TEST_ELF) $(TEST_OBJ)
	@mkdir -p $(PREFIX)/test/
	@rm test/*.o
	@mv test/*.elf $(PREFIX)/test
	@install $(PREFIX)/$(TEST_ELF) $(PREFIX)/$(TEST6_ELF)
	
tst: test

$(PREFIX)/include/pico_defines.h: FORCE
	@mkdir -p $(PREFIX)/lib
	@mkdir -p $(PREFIX)/include
	@bash ./mkdeps.sh $(PREFIX) $(OPTIONS)


deps: $(PREFIX)/include/pico_defines.h



lib: mod core
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
	@echo -e "`size -t $(PREFIX)/lib/$(LIBNAME)`"

loop: mod core
	mkdir -p $(PREFIX)/test
	@$(CC) -c -o $(PREFIX)/modules/pico_dev_loop.o modules/pico_dev_loop.c $(CFLAGS)
	@$(CC) -c -o $(PREFIX)/loop_ping.o test/loop_ping.c $(CFLAGS) -ggdb

units: mod core lib $(UNITS_OBJ)
	@echo -e "\n\t[UNIT TESTS SUITE]"
	@mkdir -p $(PREFIX)/test
	@echo -e "\t[CC] units.o"
	@$(CC) -c -o $(PREFIX)/test/units.o test/units.c $(CFLAGS) -I stack -I modules -I includes -I test/unit 
	@echo -e "\t[LD] $(PREFIX)/test/units"
	@$(CC) -o $(PREFIX)/test/units $(CFLAGS) $(PREFIX)/test/units.o -lcheck -lm -pthread -lrt $(UNITS_OBJ) 
	@$(CC) -o $(PREFIX)/test/modunit_pico_protocol.elf $(CFLAGS) -I. test/unit/modunit_pico_protocol.c stack/pico_tree.c -lcheck -lm -pthread -lrt $(UNITS_OBJ)
	@$(CC) -o $(PREFIX)/test/modunit_pico_frame.elf $(CFLAGS) -I. test/unit/modunit_pico_frame.c stack/pico_tree.c -lcheck -lm -pthread -lrt $(UNITS_OBJ)
	@$(CC) -o $(PREFIX)/test/modunit_seq.elf $(CFLAGS) -I. test/unit/modunit_seq.c -lcheck -lm -pthread -lrt $(UNITS_OBJ) $(PREFIX)/lib/libpicotcp.a
	@$(CC) -o $(PREFIX)/test/modunit_tcp.elf $(CFLAGS) -I. test/unit/modunit_pico_tcp.c -lcheck -lm -pthread -lrt $(UNITS_OBJ) $(PREFIX)/lib/libpicotcp.a
	@$(CC) -o $(PREFIX)/test/modunit_dns_client.elf $(CFLAGS) -I. test/unit/modunit_pico_dns_client.c -lcheck -lm -pthread -lrt $(UNITS_OBJ) $(PREFIX)/lib/libpicotcp.a
	@$(CC) -o $(PREFIX)/test/modunit_mdns.elf $(CFLAGS) -I. test/unit/modunit_pico_mdns.c -lcheck -lm -pthread -lrt $(UNITS_OBJ) $(PREFIX)/lib/libpicotcp.a
	@$(CC) -o $(PREFIX)/test/modunit_dev_loop.elf $(CFLAGS) -I. test/unit/modunit_pico_dev_loop.c -lcheck -lm -pthread -lrt $(UNITS_OBJ)
	@$(CC) -o $(PREFIX)/test/modunit_ipv6_nd.elf $(CFLAGS) -I. test/unit/modunit_pico_ipv6_nd.c -lcheck -lm -pthread -lrt $(UNITS_OBJ) $(PREFIX)/lib/libpicotcp.a
	@$(CC) -o $(PREFIX)/test/modunit_pico_stack.elf $(CFLAGS) -I. test/unit/modunit_pico_stack.c -lcheck -lm -pthread -lrt $(UNITS_OBJ) $(PREFIX)/lib/libpicotcp.a
	@$(CC) -o $(PREFIX)/test/modunit_sntp_client.elf $(CFLAGS) -I. test/unit/modunit_pico_sntp_client.c -lcheck -lm -pthread -lrt $(UNITS_OBJ)
	@$(CC) -o $(PREFIX)/test/modunit_ipfilter.elf $(CFLAGS) -I. test/unit/modunit_pico_ipfilter.c stack/pico_tree.c -lcheck -lm -pthread -lrt $(UNITS_OBJ)
	@$(CC) -o $(PREFIX)/test/modunit_queue.elf $(CFLAGS) -I. test/unit/modunit_queue.c  -lcheck -lm -pthread -lrt $(UNITS_OBJ)

devunits: mod core lib
	@echo -e "\n\t[UNIT TESTS SUITE: device drivers]"
	@mkdir -p $(PREFIX)/test/unit/device/
	@echo -e "\t[CC] picotcp_mock.o"
	@$(CC) -c -o $(PREFIX)/test/unit/device/picotcp_mock.o $(CFLAGS) -I stack -I modules -I includes -I test/unit test/unit/device/picotcp_mock.c
	@$(CC) -c -o $(PREFIX)/test/unit/device/unit_dev_vde.o $(CFLAGS) -I stack -I modules -I includes -I test/unit test/unit/device/unit_dev_vde.c
	@echo -e "\t[LD] $(PREFIX)/test/devunits"
	@$(CC) -o $(PREFIX)/test/devunits $(CFLAGS) -I stack $(PREFIX)/test/unit/device/*.o -lcheck -lm -pthread -lrt

units_mm: mod core lib
	@echo -e "\n\t[UNIT TESTS SUITE]"
	@mkdir -p $(PREFIX)/test
	@echo -e "\t[CC] units_mm.o"
	@$(CC) -c -o $(PREFIX)/test/units_mm.o test/unit/unit_mem_manager.c $(CFLAGS) -I stack -I modules -I includes -I test/unit
	@echo -e "\t[LD] $(PREFIX)/test/units"
	@$(CC) -o $(PREFIX)/test/units_mm $(CFLAGS) $(PREFIX)/test/units_mm.o -lcheck -lm -pthread -lrt


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

dummy: mod core lib $(DUMMY_EXTRA)
	@echo testing configuration...
	@$(CC) -c -o test/dummy.o test/dummy.c $(CFLAGS)
	@$(CC) -o dummy test/dummy.o $(DUMMY_EXTRA) $(PREFIX)/lib/libpicotcp.a $(LDFLAGS)
	@echo done.
	@rm -f test/dummy.o dummy 


FORCE:
