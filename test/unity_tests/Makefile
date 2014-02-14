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

GENERATE_TEST_RUNNER = ../../../Unity/auto/generate_test_runner.rb
GENERATE_MOCK = ../../../CMock/lib/cmock.rb

LIBS=Libraries


TEST_FRAMEWORK = $(UNITY)/unity.o \
	  $(CMOCK)/cmock.o \

TEST_FRAMEWORK_CFLAGS = -I$(UNITY) -I$(CMOCK)

ZMQ_SRC = $(PICOTCP)/modules/pico_zmq.c \
    $(PICOTCP)/modules/pico_zmq.h

TEST_ZMQ_TESTS = Testzmq_tests.c
TEST_ZMTP_TESTS = Testzmtp_tests.c
TEST_VECTOR_TESTS = Testpico_vector.c
TEST_VECTOR_EXTENSION_TESTS = Testpico_vector_extension.c

TEST_ZMQ_TESTS_RUNNER = Testzmq_tests_Runner.c
TEST_ZMTP_TESTS_RUNNER = Testzmtp_tests_Runner.c
TEST_VECTOR_TESTS_RUNNER = Testpico_vector_Runner.c
TEST_VECTOR_EXTENSION_TESTS_RUNNER = Testpico_vector_extension_Runner.c

ZMQ_TESTS_SRC = $(MOCKS)/Mockpico_zmtp.o \
      $(MOCKS)/Mockpico_vector.o \
      $(MOCKS)/Mockpico_ipv4.o \
	  $(MOCKS)/Mockpico_mm.o \
	  $(TEST_ZMQ_TESTS_RUNNER) \

ZMTP_TESTS_SRC = $(TEST_ZMTP_TESTS) \
      $(MOCKS)/Mockpico_socket.o \
      $(MOCKS)/Mockpico_vector.o \
      $(MOCKS)/Mockpico_mm.o \
      $(TEST_ZMTP_TESTS_RUNNER) \

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

CFLAGS += -DPICO_SUPPORT_MM -DPICO_SUPPORT_MM_PROFILING


all: zmtp_tests zmq_tests vector_tests vector_extension_tests

$(TEST_FRAMEWORK): %.o : %.c
	@$(CC) -c $(TEST_FRAMEWORK_CFLAGS) $< -o $@

$(ZMQ_TESTS_SRC): %.o : %.c
	@$(CC) -c $(TEST_FRAMEWORK_CFLAGS) -DPICO_SUPPORT_MM -DPICO_SUPPORT_MM_PROFILING -I$(PICOTCP)/modules/ -I$(MOCKS) -I$(PICOTCP)/include/ $< -o $@

$(ZMTP_TESTS_SRC): %.o : %.c
	@$(CC) -c $(TEST_FRAMEWORK_CFLAGS) -DPICO_SUPPORT_MM -DPICO_SUPPORT_MM_PROFILING -I$(PICOTCP)/modules/ -I$(MOCKS) -I$(PICOTCP)/include/ $< -o $@

generate_zmq_mocks:
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMQ_TESTS) $(TEST_ZMQ_TESTS_RUNNER)
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../modules/pico_zmtp.h ../../include/pico_vector.h ../../modules/pico_mm.h ../../modules/pico_ipv4.h
	
generate_zmtp_mocks:
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMTP_TESTS) $(TEST_ZMTP_TESTS_RUNNER)
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../include/pico_vector.h ../../modules/pico_mm.h
	#ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../include/pico_socket.h
	
zmq_tests: generate_zmq_mocks $(TEST_FRAMEWORK) $(ZMQ_TESTS_SRC) $(TEST_ZMQ_TESTS)
	@mv $(UNITY)/*.o ./obj/
	@mv $(CMOCK)/*.o ./obj/
	@mv ./mocks/*.o ./obj/
	#@mv $(PICOTCP)stack/*.o ./obj/
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_ZMQ_TESTS) $(TEST_ZMQ_TESTS_RUNNER)


zmtp_tests: generate_zmtp_mocks $(TEST_FRAMEWORK) $(ZMTP_TESTS_SRC)
	@mv $(UNITY)/*.o ./obj/
	@mv $(CMOCK)/*.o ./obj/
	@mv ./mocks/*.o ./obj/
	$(CC) -I$(PICOTCP)/include -I$(PICOTCP)/modules -c -o ./obj/pico_tree.o $(PICOTCP)/stack/pico_tree.c
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_ZMTP_TESTS) $(TEST_ZMTP_TESTS_RUNNER)

vector_tests: $(TEST_FRAMEWORK) $(VECTOR_TESTS_SRC)
	ruby $(GENERATE_TEST_RUNNER) $(TEST_VECTOR_TESTS) $(TEST_VECTOR_TESTS_RUNNER)
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(VECTOR_TESTS_SRC) $(TEST_VECTOR_TESTS_RUNNER)

vector_extension_tests: $(TEST_FRAMEWORK) $(VECTOR_EXTENSION_TESTS_SRC)
	ruby $(GENERATE_TEST_RUNNER) $(TEST_VECTOR_EXTENSION_TESTS) $(TEST_VECTOR_EXTENSION_TESTS_RUNNER)
	$(CC) $(CFLAGS) -o $@ $(TEST_FRAMEWORK) $(VECTOR_EXTENSION_TESTS_SRC) $(TEST_VECTOR_EXTENSION_TESTS_RUNNER)

clean:
	rm -vf demo.elf demo.bin *.o ./obj/*.o
	rm -vf zmq_tests vector_tests vector_extension_tests
