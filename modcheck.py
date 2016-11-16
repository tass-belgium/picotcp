#!/usr/bin/python
import os,sys
import subprocess


print "Scroll down for summary"
print ""
print ""

f = open('MODTREE')
mods = {}
commands = []

def get_deps(mod):
  if not mod in mods.keys():
    return []
  deps = mods[mod]
  retlist = [mod]
  for i in deps.split(' '):
    retlist.append(i)
    for j in get_deps(i):
      retlist.append(j)
  return retlist
  

while(True):
  r = f.readline()
  if r == '':
    break
  if r != '\n':
    strings = r.split(':')
    mod = strings[0]
    deps = strings[1].rstrip('\n')
    mods[mod] = deps.strip(' ')

for k,v in mods.iteritems():
  command = 'make dummy '
  deps = get_deps(k)
  for i in mods.keys():
    if i in deps:
      command += i + "=1 "
    else:
      command += i + "=0 "
  commands.append(command)

endResult = []
failed = 0

for i in commands:
  print 'Checking config:\n\t%s' % i

  subprocess.call(['make','clean'])
  sys.stdout.flush()
  sys.stderr.flush()

  args = i.split(' ')

  # Remove the last item (which is a blank)
  ret = subprocess.call(args[:-1])
  sys.stdout.flush()
  sys.stderr.flush()

  if ret == 0:
    print "**********************************************************"
    print "*******************  CONFIG PASSED!  *******************"
    endResult.append({"test": i, "result": "PASS"})
  else:
    failed += 1
    print "**********************************************************"
    print "*******************  CONFIG FAILED!  *******************"
    endResult.append({"test": i, "result": "FAIL"})
  print "**********************************************************"

print ""
print "***************************************************************************"
print "                           Executive Summary"
print "***************************************************************************"
print ""

for r in endResult:
  print "Test:", r["test"]
  print "Status:", r["result"]
  print ""

print "***********************"
print "%d out of %d Failed" % (failed, len(endResult))
print "***********************"

if failed:
  sys.exit(1)
else:
  sys.exit(0)
