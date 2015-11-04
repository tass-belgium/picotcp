#!/bin/bash
rm -f /tmp/pico-mem-report-*

ASAN_OPTIONS="detect_leaks=0" ./build/test/units || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_fragments.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_pico_stack.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_pico_protocol.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_pico_frame.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_seq.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_tcp.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_dev_loop.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_dns_client.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_dns_common.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_sntp_client.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_ipv6_nd.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_mdns.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_dns_sd.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_ipfilter.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_queue.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_tftp.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_aodv.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_dev_ppp.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_mld.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_igmp.elf || exit 1
ASAN_OPTIONS="detect_leaks=0" ./build/test/modunit_hotplug_detection.elf || exit 1

MAXMEM=`cat /tmp/pico-mem-report-* | sort -r -n |head -1`
echo
echo
echo
echo "MAX memory used: $MAXMEM"
rm -f /tmp/pico-mem-report-*

echo "SUCCESS!" && exit 0
