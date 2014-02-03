PICOTCP?=/home/sam/Documenten/Samwise/picotcp

TCPREFIX = 
CC      = $(TCPREFIX)gcc
AS      = $(TCPREFIX)gcc
LD      = $(TCPREFIX)gcc
CP      = $(TCPREFIX)objcopy
OD      = $(TCPREFIX)objdump
GDBTUI  = $(TCPREFIX)gdbtui

UNITY = /home/sam/Documenten/Samwise/Unity/src
CMOCK = /home/sam/Documenten/Samwise/CMock/src
MOCKS = ./mocks

LIBS=Libraries

SRC = Testzmq_tests_Runner.c \
      Testzmq_tests.c \
      $(MOCKS)/Mockpico_zmtp.c \
      $(UNITY)/unity.c \
	  $(CMOCK)/cmock.c \
	  #Libraries/picotcp/lib/libpicotcp.a
      

CFLAGS += -I$(PICOTCP)/include/ -I$(PICOTCP)/modules/ -I$(UNITY) -I$(CMOCK) -I$(MOCKS)

all: test

test: $(SRC)
	$(CC) $(CFLAGS) -o $@ $(SRC)

clean:
	rm -f demo.elf demo.bin
