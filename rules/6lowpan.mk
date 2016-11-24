OPTIONS+=-DPICO_SUPPORT_6LOWPAN -DPICO_SUPPORT_IPV6

################################################################################
# DEFAULTS
################################################################################

# Enable the 6LoWPAN IPHC compression scheme by default
6LOWPAN_IPHC?=1

# Disable MAC framing for mac-enabled radios, disabled by default
6LOWPAN_NOMAC?=0

# Enable IEEE802.15.4 device support by default
IEEE802154?=1

# Enable radiotest packet dump
RADIOTEST_PCAP?=0

################################################################################
# 6LOWPAN OPTIONS
################################################################################

ifeq ($(6LOWPAN_IPHC), 1)
	EXTRA_CFLAGS+=-DPICO_6LOWPAN_IPHC_ENABLED
endif

ifeq ($(6LOWPAN_NOMAC), 1)
	EXTRA_CFLAGS+=-DPICO_6LOWPAN_NOMAC
endif

################################################################################
# 6LOWPAN LINK LAYER OPTIONS
################################################################################

# IEEE802.15.4 with or without mac layer
ifeq ($(IEEE802154), 1)
	6LOWPAN_OPTIONS+=-DPICO_SUPPORT_802154
	POSIX_OBJ+=modules/pico_dev_radiotest.o \
			modules/pico_dev_radio_mgr.o
endif

OPTIONS+=$(6LOWPAN_OPTIONS)

# Append module objects
MOD_OBJ+=$(LIBBASE)modules/pico_6lowpan_ll.o
MOD_OBJ+=$(LIBBASE)modules/pico_6lowpan.o
MOD_OBJ+=$(LIBBASE)modules/pico_802154.o

# Count the amount of supported 6LoWPAN Link Layer protocols based on the amount of words in
# $6LOWPAN_OPTIONS. This allows us to define a static array that can be initialized with the 6LoWPAN
# link layer protocol definitions for the supported link layer protocols. This happens upon
# initialization of the 6LoWPAN_LL-layer.
EXTRA_CFLAGS+=-DPICO_6LOWPAN_LLS=$(words $(6LOWPAN_OPTIONS))

################################################################################
# RADIOTEST
################################################################################

ifeq ($(RADIOTEST_PCAP), 1)
	EXTRA_CFLAGS+=-DRADIO_PCAP
	TEST_LDFLAGS+=-lpcap
endif
