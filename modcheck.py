#!/usr/bin/python
import os,sys
import subprocess

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
  command = 'make '
  deps = get_deps(k)
  for i in mods.keys():
    if i in deps:
      command += i + "=1 "
    else:
      command += i + "=0 "
  print command
  commands.append(command)


for i in commands:
  print 'Checking config:\n\t%s\n' % i
  os.system('make clean >/dev/null')
  args = i.split(' ')
  
  subprocess.check_call(i, shell=True,stdout=None, stderr=None)==0 or sys.exit(1)
sys.exit(0)
