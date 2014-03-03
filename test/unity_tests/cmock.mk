
ifndef CMOCK
$(error Please point CMOCK variable to your cmock directory)
endif

ifndef UNITY
$(error Please point UNITY variable to your unity directory)
endif


# ----------------------------------------

GENERATE_TEST_RUNNER = ruby $(UNITY)/auto/generate_test_runner.rb
GENERATE_MOCK = ruby $(CMOCK)/lib/cmock.rb

GTRFLAGS = 
GMFLAGS = 

CMOCK_OBJ = $(CMOCK)/src/cmock.o
UNITY_OBJ = $(UNITY)/src/unity.o

$(CMOCK_OBJ) $(UNITY_OBJ) : CPPFLAGS += -I$(UNITY)/src -I$(CMOCK)/src

CMOCK_DEP =  $(CMOCK_OBJ) $(UNITY_OBJ)

# ----------------------------------------

# files in the pico/include dir
cmock_make__picoincludefiles = $(shell ls $(PICOTCP)/include/*h)

# ----------------------------------------
define MockRuleTemplate
$1_incldir = $(if $(findstring $1,$(cmock_make__picoincludefiles)), include, modules)

Mock$(1).h : $(PICOTCP)/$$($1_incldir)/$(1).h
	mkdir -p mocks
	$(GENERATE_MOCK) $(GMFLAGS) $$^

Mock$(1).o : mocks/Mock$(1).c mocks/Mock$(1).h
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $$^ -o $$@
endef
# ------------------------------------------
define GenerateRulesForMocks
$(foreach mock, \
					$(strip $(1)), \
					$(eval $(call MockRuleTemplate,$(subst .h,,$(mock)))))
endef

# -----------------------------------

Mock%.o: CPPFLAGS += -DPICO_SUPPORT_MM

# -----------------------------------

.SECONDEXPANSION:
%Runner.c : $$(subst _Runner,,$$@)
	$(GENERATE_TEST_RUNNER) $(GTFFLAGS) $^ $@

%Runner.o: %Runner.c

# -----------------------------------