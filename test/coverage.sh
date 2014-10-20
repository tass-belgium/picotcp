#!/bin/bash
./test/units.sh || exit 1
./test/autotest.sh || exit 2
exit 0
