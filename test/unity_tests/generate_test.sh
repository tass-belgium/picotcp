#!/bin/bash

ruby ../../../Unity/auto/generate_test_runner.rb Testzmq_tests.c ./Testzmq_tests_Runner.c
ruby ../../../CMock/lib/cmock.rb --plugins="expect;callback" ../../modules/pico_zmtp.h

make && ./test
