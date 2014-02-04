#!/bin/bash

ruby ../../../Unity/auto/generate_test_runner.rb Testzmtp_tests.c ./Testzmtp_tests_Runner.c
ruby ../../../CMock/lib/cmock.rb --plugins="expect;callback;ignore" ../../include/pico_socket.h

make zmtp_tests && ./zmtp_tests
