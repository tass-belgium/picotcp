OPTIONS+=-DPICO_SUPPORT_SIXLOWPAN -DPICO_SUPPORT_IPV6 -DPICO_SUPPORT_IEEE802154
MOD_OBJ+=$(LIBBASE)modules/pico_sixlowpan.o
MOD_OBJ+=$(LIBBASE)modules/pico_dev_ieee802154.o
MOD_OBJ+=$(LIBBASE)modules/pico_ieee802154.o
MOD_OBJ+=$(LIBBASE)modules/pico_sixlowpan_mesh.o
