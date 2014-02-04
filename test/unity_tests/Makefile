PICOTCP?=../../

TCPREFIX = 
CC      = $(TCPREFIX)gcc
AS      = $(TCPREFIX)gcc
LD      = $(TCPREFIX)gcc
CP      = $(TCPREFIX)objcopy
OD      = $(TCPREFIX)objdump
GDBTUI  = $(TCPREFIX)gdbtui

UNITY = ../../../Unity/src
CMOCK = ../../../CMock/src
MOCKS = ./mocks

LIBS=Libraries

ZMQ_TESTS_SRC = Testzmq_tests_Runner.c \
      Testzmq_tests.c \
      $(MOCKS)/Mockpico_zmtp.c \

ZMTP_TESTS_SRC = Testzmtp_tests_Runner.c \
      Testzmtp_tests.c \
      $(MOCKS)/Mockpico_socket.c \
      $(PICOTCP)/modules/pico_zmtp.c \
      $(PICOTCP)/stack/pico_tree.c

TEST_FRAMEWORK = $(UNITY)/unity.c \
	  $(CMOCK)/cmock.c \
      

CFLAGS += -I$(PICOTCP)/include/ -I$(PICOTCP)/modules/ -I$(UNITY) -I$(CMOCK) -I$(MOCKS)

all: zmtp_tests zmq_tests


zmq_tests: $(TEST_FRAMEWORK) $(ZMQ_TESTS_SRC)
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(ZMQ_TESTS_SRC)

zmtp_tests: $(TEST_FRAMEWORK) $(ZMTP_TESTS_SRC)
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(ZMTP_TESTS_SRC)

clean:
	rm -f demo.elf demo.bin
