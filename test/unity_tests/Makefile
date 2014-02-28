PICOTCP?=../..

TCPREFIX = 
CC      = $(TCPREFIX)gcc
AS      = $(TCPREFIX)gcc
LD      = $(TCPREFIX)gcc
CP      = $(TCPREFIX)objcopy
OD      = $(TCPREFIX)objdump
GDBTUI  = $(TCPREFIX)gdbtui

UNITY?= ../../../Unity
CMOCK?= ../../../CMock
MOCKS= ./mocks

GENERATE_TEST_RUNNER = $(UNITY)/auto/generate_test_runner.rb
GENERATE_MOCK = $(CMOCK)/lib/cmock.rb

LIBS=Libraries


TEST_FRAMEWORK = $(UNITY)/src/unity.o \
	  $(CMOCK)/src/cmock.o \

TEST_FRAMEWORK_CFLAGS = -I$(UNITY)/src -I$(CMOCK)/src

ZMQ_SRC = $(PICOTCP)/modules/pico_zmq.c \
    $(PICOTCP)/modules/pico_zmq.h

TEST_ZMQ_TESTS = Testzmq_tests.c
TEST_ZMTP_TESTS = Testzmtp_tests.c
TEST_VECTOR_TESTS = Testpico_vector.c
TEST_VECTOR_EXTENSION_TESTS = Testpico_vector_extension.c
TEST_ZMTP_DATAFLOW = Testzmtp_dataflow.c

TEST_ZMQ_TESTS_RUNNER = Testzmq_tests_Runner.c
TEST_ZMTP_TESTS_RUNNER = Testzmtp_tests_Runner.c
TEST_VECTOR_TESTS_RUNNER = Testpico_vector_Runner.c
TEST_VECTOR_EXTENSION_TESTS_RUNNER = Testpico_vector_extension_Runner.c
TEST_ZMTP_DATAFLOW_RUNNER = Testzmtp_dataflow_Runner.c

ZMQ_TESTS_SRC = $(MOCKS)/Mockpico_zmtp.o \
      $(MOCKS)/Mockpico_vector.o \
      $(MOCKS)/Mockpico_ipv4.o \
	  $(MOCKS)/Mockpico_mm.o \

ZMTP_TESTS_SRC = $(MOCKS)/Mockpico_socket.o \
      $(MOCKS)/Mockpico_vector.o \
      $(MOCKS)/Mockpico_mm.o \
      $(MOCKS)/Mockpico_tree.o \

ZMTP_DATAFLOW_SRC = $(MOCKS)/Mockpico_socket.o \
    $(MOCKS)/Mockpico_mm.o \

VECTOR_TESTS_SRC = $(TEST_VECTOR_TESTS) \
      $(MOCKS)/Mockpico_mm.o \
      ../../stack/pico_vector.o

VECTOR_EXTENSION_TESTS_SRC = $(TEST_VECTOR_EXTENSION_TESTS) \
      $(MOCKS)/Mockpico_mm.o \
      ../../stack/pico_vector.o


PLUGIN_EXPECT = --plugins="expect;"
PLUGIN_EXPECT_CALLBACK = --ignore=args_only --plugins="expect;callback"
PLUGIN_EXPECT_CALLBACK_IGNORE = --ignore=args_only --plugins="expect;callback;ignore"

USE_MEM_MANAGER = -DPICO_SUPPORT_MM -DPICO_SUPPORT_MM_PROFILING

CFLAGS += -ggdb -Wall -Wdeclaration-after-statement -W -Wextra -Wshadow -Wconversion -Wcast-qual -Wwrite-strings -Wmissing-field-initializers -I$(PICOTCP)/include/ -I$(PICOTCP)/modules/ -I$(UNITY)/src -I$(CMOCK)/src -I$(MOCKS)

CFLAGS += $(USE_MEM_MANAGER)

all: 
	make zmtp_tests 
	-rm -f ./obj/*
	make zmq_tests 
	-rm -f ./obj/*
	make vector_tests
	-rm -f ./obj/* 
	make vector_extension_tests

$(TEST_FRAMEWORK): %.o : %.c
	@$(CC) -ggdb -c $(TEST_FRAMEWORK_CFLAGS) $< -o $@

$(ZMQ_TESTS_SRC): %.o : %.c
	@$(CC) -ggdb -c $(TEST_FRAMEWORK_CFLAGS) $(USE_MEM_MANAGER) -I$(PICOTCP)/modules/ -I$(MOCKS) -I$(PICOTCP)/include/ $< -o $@

$(ZMTP_TESTS_SRC): %.o : %.c
	@$(CC) -ggdb -c $(TEST_FRAMEWORK_CFLAGS) $(USE_MEM_MANAGER) -I$(PICOTCP)/modules/ -I$(MOCKS) -I$(PICOTCP)/include/ $< -o $@

$(ZMTP_DATAFLOW_SRC): %.o : %.c
	@$(CC) -ggdb -c $(TEST_FRAMEWORK_CFLAGS) $(USE_MEM_MANAGER) -I$(PICOTCP)/modules/ -I$(MOCKS) -I$(PICOTCP)/include/ $< -o $@

generate_zmq_mocks:
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMQ_TESTS) $(TEST_ZMQ_TESTS_RUNNER)
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../modules/pico_zmtp.h ../../include/pico_vector.h ../../modules/pico_mm.h ../../modules/pico_ipv4.h
	
generate_zmtp_mocks:
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMTP_TESTS) $(TEST_ZMTP_TESTS_RUNNER)
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../include/pico_vector.h ../../modules/pico_mm.h ../../include/pico_tree.h
	#ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../include/pico_socket.h 

generate_zmtp_dataflow_mocks:
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMTP_DATAFLOW) $(TEST_ZMTP_DATAFLOW_RUNNER)

generate_vector_mocks:
	ruby $(GENERATE_TEST_RUNNER) $(TEST_ZMTP_TESTS) $(TEST_ZMTP_TESTS_RUNNER)
	ruby $(GENERATE_MOCK) $(PLUGIN_EXPECT_CALLBACK_IGNORE) ../../modules/pico_mm.h
	
prepare_objects:
	@mkdir -p ./obj
	-rm -f ./obj/*
	-mv $(UNITY)/src/*.o ./obj/
	-mv $(CMOCK)/src/*.o ./obj/
	-mv ./mocks/*.o ./obj/
	
zmq_tests: generate_zmq_mocks $(TEST_FRAMEWORK) $(ZMQ_TESTS_SRC) $(TEST_ZMQ_TESTS)
	make prepare_objects
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_ZMQ_TESTS) $(TEST_ZMQ_TESTS_RUNNER)


zmtp_tests: generate_zmtp_mocks $(TEST_FRAMEWORK) $(ZMTP_TESTS_SRC)
	make prepare_objects
	#$(CC) -I$(PICOTCP)/include -I$(PICOTCP)/modules -c -o ./obj/pico_tree.o $(PICOTCP)/stack/pico_tree.c
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_ZMTP_TESTS) $(TEST_ZMTP_TESTS_RUNNER)

zmtp_dataflow: generate_zmtp_dataflow_mocks $(TEST_FRAMEWORK) $(ZMTP_DATAFLOW_SRC)
	make prepare_objects
	#$(CC) -I$(PICOTCP)/include -I$(PICOTCP)/modules -c -o ./obj/pico_tree.o $(PICOTCP)/stack/pico_tree.c
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_ZMTP_DATAFLOW) $(TEST_ZMTP_DATAFLOW_RUNNER)

vector_tests: $(TEST_FRAMEWORK) $(VECTOR_TESTS_SRC)
	make prepare_objects
	ruby $(GENERATE_TEST_RUNNER) $(TEST_VECTOR_TESTS) $(TEST_VECTOR_TESTS_RUNNER)
	$(CC) -I$(PICOTCP)/include -I$(PICOTCP)/modules $(USE_MEM_MANAGER) -c -o ./obj/pico_vector.o ../../stack/pico_vector.c
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_VECTOR_TESTS) $(TEST_VECTOR_TESTS_RUNNER)

vector_extension_tests: $(TEST_FRAMEWORK) $(VECTOR_EXTENSION_TESTS_SRC)
	make prepare_objects
	ruby $(GENERATE_TEST_RUNNER) $(TEST_VECTOR_EXTENSION_TESTS) $(TEST_VECTOR_EXTENSION_TESTS_RUNNER)
	$(CC) -I$(PICOTCP)/include -I$(PICOTCP)/modules $(USE_MEM_MANAGER) -c -o ./obj/pico_vector.o ../../stack/pico_vector.c
	$(CC) $(CFLAGS) -o $@ ./obj/* $(TEST_VECTOR_EXTENSION_TESTS) $(TEST_VECTOR_EXTENSION_TESTS_RUNNER)

clean:
	rm -vrf demo.elf demo.bin *.o ./obj/
	rm -vrf zmq_tests vector_tests vector_extension_tests zmtp_tests
