PREFIX?=../../build
CFLAGS+=-I../../include/ -I../../modules -I../../build/include -I . -ggdb


$(PREFIX)/examples/%.o: %.c 
	@mkdir -p $(PREFIX)/examples
	@echo -e "\t[CC] $@"
	@$(CC) -c $(CFLAGS) -o $@ $< 

OBJS:= \
$(PREFIX)/examples/dhcp_client.o \
$(PREFIX)/examples/dhcp_server.o \
$(PREFIX)/examples/dns_sd.o \
$(PREFIX)/examples/dnsclient.o \
$(PREFIX)/examples/mdns.o \
$(PREFIX)/examples/multicast_recv.o \
$(PREFIX)/examples/multicast_ip6_recv.o \
$(PREFIX)/examples/multicast_send.o \
$(PREFIX)/examples/multicast_ip6_send.o \
$(PREFIX)/examples/natbox.o \
$(PREFIX)/examples/noop.o \
$(PREFIX)/examples/ping.o \
$(PREFIX)/examples/slaacv4.o \
$(PREFIX)/examples/sntp.o \
$(PREFIX)/examples/tcpbench.o \
$(PREFIX)/examples/tcpclient.o \
$(PREFIX)/examples/tcpecho.o \
$(PREFIX)/examples/tftp.o \
$(PREFIX)/examples/udp_client.o \
$(PREFIX)/examples/udp_echo.o \
$(PREFIX)/examples/udpnat.o \
$(PREFIX)/examples/udp_sendto_test.o \
$(PREFIX)/examples/iperfc.o \


all: $(OBJS)
