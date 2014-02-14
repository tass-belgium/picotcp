#!/bin/bash

./build/test/units || exit 1
./build/test/modunit_pico_protocol.elf || exit 1
