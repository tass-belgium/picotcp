#!/bin/bash
# By Daniele.
#set -x
filename=$1
if [ [x$1] == [x] ]; then
    echo USAGE: $0 filename.c
    exit 4
fi

#CMOCK="../CMock/lib/cmock.rb"

bname=`basename $filename`
cat $filename |grep static|grep \( | grep \) >/tmp/$bname 

if (test -f ./test/unit/modunit_$bname); then
    echo The destination file ./test/unit/modunit_$bname already exists. Exiting...
    exit 0
fi

cat $filename |grep "\#include " > ./test/unit/modunit_$bname
MYSELF=`echo $bname | cut -d"." -f1`.h
INCLUDES=`cat $filename |grep "\#include \"" |grep -v $MYSELF| cut -d '"' -f 2`

echo includes are:
echo $INCLUDES
echo "#include \"$filename\"" >>./test/unit/modunit_$bname
echo "#include \"check.h\"" >>./test/unit/modunit_$bname
echo >> ./test/unit/modunit_$bname
echo >> ./test/unit/modunit_$bname

while read fn ; do
    fname=`echo $fn | cut -d "(" -f 1| cut -d" " -f 3`
    echo "START_TEST(tc_$fname)"               >>./test/unit/modunit_$bname 
    echo "{"                                >>./test/unit/modunit_$bname
    echo "   /* TODO: test this: $fn */"    >>./test/unit/modunit_$bname
    echo "}"                                >>./test/unit/modunit_$bname
    echo "END_TEST"                         >>./test/unit/modunit_$bname
done </tmp/$bname

echo >> ./test/unit/modunit_$bname
echo >> ./test/unit/modunit_$bname
echo "Suite *pico_suite(void)                       
{
    Suite *s = suite_create(\"PicoTCP\");             
"  >> ./test/unit/modunit_$bname

while read fn ; do
    fname=`echo $fn | cut -d "(" -f 1| cut -d" " -f 3` 
    echo "    TCase *TCase_$fname = tcase_create(\"Unit test for $fname\");" >> ./test/unit/modunit_$bname
done </tmp/$bname

echo >> ./test/unit/modunit_$bname
echo >> ./test/unit/modunit_$bname

while read fn ; do
    fname=`echo $fn | cut -d "(" -f 1| cut -d" " -f 3` 
    echo "    tcase_add_test(TCase_$fname, tc_$fname);" >> ./test/unit/modunit_$bname
    echo "    suite_add_tcase(s, TCase_$fname);" >> ./test/unit/modunit_$bname
done </tmp/$bname

echo "return s;">> ./test/unit/modunit_$bname
echo "}">> ./test/unit/modunit_$bname

echo "                      
int main(void)                      
{                       
    int fails;                      
    Suite *s = pico_suite();                        
    SRunner *sr = srunner_create(s);                        
    srunner_run_all(sr, CK_NORMAL);                     
    fails = srunner_ntests_failed(sr);                      
    srunner_free(sr);                       
    return fails;                       
}" >>./test/unit/modunit_$bname


echo Gernerated test ./test/unit/modunit_$bname
#echo Generating mocks...
#mkdir -p mocks
#
#CFILES=""
#for i in $INCLUDES; do
#    ii=`find -name $i | grep -v build`
#    ruby $CMOCK $ii
#    CFILE=`basename $ii |cut -d "." -f 1`.c
#    CFILES="$CFILES mocks/Mock$CFILE"
#done
ELF=`echo build/test/modunit_$bname | sed -e "s/\.c/.elf/g"`

echo 
echo

MOCKS=$(gcc -I include/ -I modules/ -I. test/unit/modunit_$bname $CFILES -lcheck -pthread -lm -lrt -o $ELF 2>&1 |grep "undefined reference to" | sed -e "s/.*\`//g" | sed -e "s/'.*$//g" |sort | uniq) 

for m in $MOCKS; do
    decl=`grep -R $m * |grep -v ");" | grep -v Binary | cut -d ":" -f 2`
    echo $decl >> ./test/unit/modunit_$bname
    echo "{"   >> ./test/unit/modunit_$bname
    echo "/* TODO: MOCK ME! */">> ./test/unit/modunit_$bname
    echo "}"   >> ./test/unit/modunit_$bname
done
gcc -I include/ -I modules/ -I. test/unit/modunit_$bname $CFILES -lcheck -pthread -lm -lrt -o $ELF && echo "Successfully compiled $ELF"

#echo " /* TODO: MOCKS NEEDED: $MOCKS */ " >>./test/unit/modunit_$bname
