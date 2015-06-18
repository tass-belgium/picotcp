OPTIONS+=-DPICO_SUPPORT_DNS_SD
MOD_OBJ+=$(LIBBASE)modules/pico_dns_sd.o $(LIBBASE)modules/pico_mdns.o $(LIBBASE)modules/pico_dns_common.o