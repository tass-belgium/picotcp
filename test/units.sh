#!/bin/bash
rm -f /tmp/pico-mem-report-*

./build/test/units || exit 1
./build/test/modunit_pico_protocol.elf || exit 1
./build/test/modunit_pico_frame.elf || exit 1

MAXMEM=`cat /tmp/pico-mem-report-* | sort -r -n |head -1`
echo
echo
echo
echo "MAX memory used: $MAXMEM"
rm -f /tmp/pico-mem-report-*

echo "SUCCESS!" && exit 0
