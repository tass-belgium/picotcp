BUILDDIR?=../../build
CFLAGS+=-I../../include/ -I../../modules -I../../build/include -I . -ggdb


$(BUILDDIR)/examples/%.o: %.c 
	@mkdir -p $(BUILDDIR)/examples
	@echo -e "\t[CC] $@"
	@$(CC) -c $(CFLAGS) -o $@ $< 

OBJS:= \
$(BUILDDIR)/examples/dhcp_client.o \
$(BUILDDIR)/examples/dhcp_server.o \
$(BUILDDIR)/examples/dns_sd.o \
$(BUILDDIR)/examples/dnsclient.o \
$(BUILDDIR)/examples/mdns.o \
$(BUILDDIR)/examples/multicast_recv.o \
$(BUILDDIR)/examples/multicast_ip6_recv.o \
$(BUILDDIR)/examples/multicast_send.o \
$(BUILDDIR)/examples/multicast_ip6_send.o \
$(BUILDDIR)/examples/natbox.o \
$(BUILDDIR)/examples/noop.o \
$(BUILDDIR)/examples/ping.o \
$(BUILDDIR)/examples/slaacv4.o \
$(BUILDDIR)/examples/sntp.o \
$(BUILDDIR)/examples/tcpbench.o \
$(BUILDDIR)/examples/tcpclient.o \
$(BUILDDIR)/examples/tcpecho.o \
$(BUILDDIR)/examples/tftp.o \
$(BUILDDIR)/examples/udp_client.o \
$(BUILDDIR)/examples/udp_echo.o \
$(BUILDDIR)/examples/udpnat.o \
$(BUILDDIR)/examples/udp_sendto_test.o \
$(BUILDDIR)/examples/iperfc.o \


all: $(OBJS)
