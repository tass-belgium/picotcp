PICOTCP?=../../

TCPREFIX = 
CC      = $(TCPREFIX)gcc-4.6
AS      = $(TCPREFIX)gcc-4.6
LD      = $(TCPREFIX)gcc-4.6
CP      = $(TCPREFIX)objcopy
OD      = $(TCPREFIX)objdump
GDBTUI  = $(TCPREFIX)gdbtui

UNITY = ../../../Unity/src
CMOCK = ../../../CMock/src
MOCKS = ./mocks

GENERATE_TEST_RUNNER = ../../../Unity/auto/generate_test_runner.rb
GENERATE_MOCK = ../../../CMock/lib/cmock.rb

LIBS=Libraries


TEST_FRAMEWORK = $(UNITY)/unity.c \
	  $(CMOCK)/cmock.c \


TEST_ZMQ_TESTS = Testzmq_tests.c
TEST_ZMTP_TESTS = Testzmtp_tests.c
TEST_VECTOR_TESTS = Testpico_vector.c
TEST_VECTOR_EXTENSION_TESTS = Testpico_vector_extension.c

TEST_ZMQ_TESTS_RUNNER = Testzmq_tests_Runner.c
TEST_ZMTP_TESTS_RUNNER = Testzmtp_tests_Runner.c
TEST_VECTOR_TESTS_RUNNER = Testpico_vector_Runner.c
TEST_VECTOR_EXTENSION_TESTS_RUNNER = Testpico_vector_extension_Runner.c

ZMQ_TESTS_SRC = $(TEST_ZMQ_TESTS) \
      $(MOCKS)/Mockpico_zmtp.c \
      $(MOCKS)/Mockpico_vector.c \
      $(MOCKS)/Mockpico_ipv4.c \
	  $(MOCKS)/Mockpico_zalloc.c \

ZMTP_TESTS_SRC = $(TEST_ZMTP_TESTS) \
      $(MOCKS)/Mockpico_socket.c \
      $(MOCKS)/Mockpico_vector.c \
      $(MOCKS)/Mockpico_zalloc.c \
      $(PICOTCP)/stack/pico_tree.c

VECTOR_TESTS_SRC = $(TEST_VECTOR_TESTS) \
      $(MOCKS)/Mockpico_zalloc.c \
      ../../stack/pico_vector.c

VECTOR_EXTENSION_TESTS_SRC = $(TEST_VECTOR_EXTENSION_TESTS) \
      $(MOCKS)/Mockpico_zalloc.c \
      ../../stack/pico_vector.c


PLUGIN_EXPECT = --plugins="expect;"
PLUGIN_EXPECT_CALLBACK = --plugins="expect;callback"
PLUGIN_EXPECT_CALLBACK_IGNORE = --plugins="expect;callback;ignore"


CFLAGS += -ggdb -Wall -Wdeclaration-after-statement -W -Wextra -Wshadow -Wconversion -Wcast-qual -Wwrite-strings -Wmissing-field-initializers -I$(PICOTCP)/include/ -I$(PICOTCP)/modules/ -I$(UNITY) -I$(CMOCK) -I$(MOCKS)


all: zmtp_tests zmq_tests vector_tests vector_extension_tests


zmq_tests: $(TEST_FRAMEWORK) $(ZMQ_TESTS_SRC)
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMQ_TESTS) $(TEST_ZMQ_TESTS_RUNNER)
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../modules/pico_zmtp.h ../../include/pico_vector.h mocks/pico_zalloc.h
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(ZMQ_TESTS_SRC) $(TEST_ZMQ_TESTS_RUNNER)


zmtp_tests: $(TEST_FRAMEWORK) $(ZMTP_TESTS_SRC)
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMTP_TESTS) $(TEST_ZMTP_TESTS_RUNNER)
	#ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../include/pico_socket.h
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT) ../../include/pico_vector.h
	#ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT) mocks/pico_zalloc.h
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(ZMTP_TESTS_SRC) $(TEST_ZMTP_TESTS_RUNNER)

vector_tests: $(TEST_FRAMEWORK) $(VECTOR_TESTS_SRC)
	ruby $(GENERATE_TEST_RUNNER) $(TEST_VECTOR_TESTS) $(TEST_VECTOR_TESTS_RUNNER)
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(VECTOR_TESTS_SRC) $(TEST_VECTOR_TESTS_RUNNER)

vector_extension_tests: $(TEST_FRAMEWORK) $(VECTOR_EXTENSION_TESTS_SRC)
	ruby $(GENERATE_TEST_RUNNER) $(TEST_VECTOR_EXTENSION_TESTS) $(TEST_VECTOR_EXTENSION_TESTS_RUNNER)
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(VECTOR_EXTENSION_TESTS_SRC) $(TEST_VECTOR_EXTENSION_TESTS_RUNNER)

clean:
	rm -f demo.elf demo.bin *.o
	rm -f zmq_tests vector_tests vector_extension_tests
