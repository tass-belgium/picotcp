#!/usr/bin/python
import glob, os
import re
import pprint

PICOPATH = '.'
INCLUDEFOLDER = 'include'
ARCHFOLDER = 'arch'
MODULESFOLDER = 'modules'

includeFiles = {}

#parse include dir
for file in glob.glob(os.path.join(PICOPATH, INCLUDEFOLDER, "*.h")):
    includeFiles[os.path.basename(file)] = os.path.join(INCLUDEFOLDER, os.path.basename(file))

#parse arch dir
for file in glob.glob(os.path.join(PICOPATH, INCLUDEFOLDER, ARCHFOLDER, "*.h")):
    key = os.path.join('arch', os.path.basename(file))
    value = os.path.join(INCLUDEFOLDER, ARCHFOLDER, os.path.basename(file))
    includeFiles[key] = value

#parse modules dir
for file in glob.glob(os.path.join(PICOPATH, MODULESFOLDER, "*.h")):
    includeFiles[os.path.basename(file)] = os.path.join(MODULESFOLDER, os.path.basename(file))

# Library from https://pypi.python.org/pypi/toposort/1.0

from functools import reduce as _reduce
def toposort(data):
    """Dependencies are expressed as a dictionary whose keys are items
and whose values are a set of dependent items. Output is a list of
sets in topological order. The first set consists of items with no
dependences, each subsequent set consists of items that depend upon
items in the preceeding sets.
"""

    # Special case empty input.
    if len(data) == 0:
        return

    # Copy the input so as to leave it unmodified.
    data = data.copy()

    # Ignore self dependencies.
    for k, v in data.items():
        v.discard(k)
    # Find all items that don't depend on anything.
    extra_items_in_deps = _reduce(set.union, data.values()) - set(data.keys())
    # Add empty dependences where needed.
    data.update({item:set() for item in extra_items_in_deps})
    while True:
        ordered = set(item for item, dep in data.items() if len(dep) == 0)
        if not ordered:
            break
        yield ordered
        data = {item: (dep - ordered)
                for item, dep in data.items()
                    if item not in ordered}
    if len(data) != 0:
        raise ValueError('Cyclic dependencies exist among these items: {}'.format(', '.join(repr(x) for x in data.items())))

def toposort_flatten(data, sort=True):
    """Returns a single list of dependencies. For any set returned by
toposort(), those items are sorted and appended to the result (just to
make the results deterministic)."""

    result = []
    for d in toposort(data):
        result.extend((sorted if sort else list)(d))
    return result

def buildDependencyList():
    #dependencyOrder = []
    dependencyOrder = {}

    for key, value in includeFiles.items():
        #deps = []
        deps = set()
        with open(os.path.join(PICOPATH, value)) as infile:
            for line in infile:
                m = re.match( r'^#.*include[ ]+[\"<](pico_.+\.h|heap\.h)[\">](?!.*?#AMALGAMATION_IGNORE)', line, re.M|re.I)
                if m:
                    val = m.group(1)
                    if val not in deps:
                        #deps.append(val)
                        deps.add(val)
            if len(deps) > 0:
                #dependencyOrder.append((key, deps))
                dependencyOrder[key] = deps

    #orderedList = topological_sort(dependencyOrder)
    orderedList = list(toposort(dependencyOrder))
    flattenedList = toposort_flatten(dependencyOrder)

    #pprint.pprint(dependencyOrder)
    #print ""

    #pprint.pprint(orderedList)
    #print ""
    #print flattenedList

    #pprint.pprint(orderedList)

    #print ""
    #for i in orderedList:
    #    print i
    return flattenedList





# Other library from http://stackoverflow.com/questions/11557241/python-sorting-a-dependency-list

def topological_sort(source):
    """perform topo sort on elements.

    :arg source: list of ``(name, set(names of dependancies))`` pairs
    :returns: list of names, with dependencies listed first
    """
    pending = [(name, set(deps)) for name, deps in source]        
    emitted = []
    while pending:
        next_pending = []
        next_emitted = []
        for entry in pending:
            print "looping"
            name, deps = entry
            deps.difference_update(set((name,)), emitted) # <-- pop self from dep, req Py2.6
            print name, deps
            if deps:
                next_pending.append(entry)
            else:
                yield name
                emitted.append(name) # <-- not required, but preserves original order
                next_emitted.append(name)
        if not next_emitted:
            raise ValueError("cyclic dependency detected: %s %r" % (name, (next_pending,)))
        pending = next_pending
        emitted = next_emitted