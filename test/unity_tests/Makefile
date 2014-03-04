
PICOTCP?=../..

include cmock.mk
include stack.mk

GMFLAGS += --ignore=args_only --plugins="expect;callback;ignore"

# To enable pico features
USE_MEM_MANAGER = -DPICO_SUPPORT_MM -DPICO_SUPPORT_MM_PROFILING
CFLAGS += $(USE_MEM_MANAGER) -ggdb

CPPFLAGS += -I$(PICOTCP)/include/ -I$(PICOTCP)/modules/

%_Runner.o %_tests.o mocks/Mock%.o: CPPFLAGS += -I$(UNITY)/src -I$(CMOCK)/src -Imocks

$(PICOTCP)/modules/%.c test_%.c: CPPFLAGS += $(PICO_WARNINGS)

.PHONY: all clean deepclean

all: Testzmtp_tests_Runner Testzmq_tests_Runner Testzmtp_dataflow_tests_Runner

TO_BE_MOCKED = pico_vector.h pico_ipv4.h pico_mm.h pico_zmtp.h pico_socket.h pico_tree.h
$(call GenerateRulesForMocks,$(TO_BE_MOCKED))

#-------------------------------------------------

Testzmq_tests_Runner.o: Mockpico_vector.h Mockpico_ipv4.h Mockpico_mm.h Mockpico_zmtp.h

#$(PICOTCP)/modules/pico_zmq.o is included in _tests.o
Testzmq_tests_Runner: $(CMOCK_DEP)  mocks/Mockpico_zmtp.o mocks/Mockpico_ipv4.o mocks/Mockpico_vector.o mocks/Mockpico_mm.o Testzmq_tests.o

#-------------------------------------------------

Testzmtp_tests_Runner.o: Mockpico_socket.h Mockpico_tree.h Mockpico_vector.h Mockpico_mm.h

Testzmtp_tests_Runner: $(CMOCK_DEP)  mocks/Mockpico_socket.o mocks/Mockpico_vector.o mocks/Mockpico_mm.o mocks/Mockpico_tree.o Testzmtp_tests.o Testzmtp_tests_Runner.o

#-------------------------------------------------

Testzmtp_dataflow_tests_Runner.o: Mockpico_socket.h Mockpico_mm.h Mockpico_tree.h $(PICOTCP)/include/pico_vector.h

Testzmtp_dataflow_tests_Runner: $(CMOCK_DEP)  mocks/Mockpico_socket.o mocks/Mockpico_mm.o mocks/Mockpico_tree.o $(PICOTCP)/stack/pico_vector.o Testzmtp_dataflow_tests.o Testzmtp_dataflow_tests_Runner.o 

#-------------------------------------------------

clean:
	rm -f *.o mocks/*.o

deepclean: clean
	rm -rf mocks *tests_Runner
