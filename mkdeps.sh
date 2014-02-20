#!/bin/bash
PREFIX=$1
shift
echo "#ifndef PICO_DEFINES_H" >$PREFIX/include/pico_defines.h
echo "#define PICO_DEFINES_H" >>$PREFIX/include/pico_defines.h
echo  >>$PREFIX/include/pico_defines.h

for i in $@; do 
    if (echo $i | grep "^-D" >/dev/null); then
        my_def=`echo $i |sed -e "s/-D//g"`
        echo "#define $my_def" >> $PREFIX/include/pico_defines.h 
    fi
done
echo "#endif" >>$PREFIX/include/pico_defines.h
