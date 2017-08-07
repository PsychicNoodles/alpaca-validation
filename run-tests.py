import subprocess
from subprocess import PIPE
import sys
import os
import time

NUM_PRINTFS = 100

ENERGY_MEASURE = "energy"
TEST_PROG = "test-suite"
tests = ["bool", "short", "int", "long", "long_long", "float", "double", "int_struct", "double_struct", "two_int", "two_float", "mixed", "eight_int", "everything", "pointer", "malloc_free", "triple_double", "param_float", "local", "mmap", "sixteen_ll", "mem_cpy", "global_write", "printf"]
results = ["1", "2", "3", "4", "5", "-12345.6", "7.0", "8", "9.0", "10 11", "12.0 13.0", "14 15 16.0", "17 18 19 20 21 22 23 24", "1 24 25 26 27 28.0 29.0", "30 31.0 testtest", "0", "32.0 33.0 34.0", "9.3", "2", "1234", "123456 234567 345678 456789 5678910 67891011 789101112 8910111213 91011121314 101112131415 111213141516 121314151617 131415161718 141516171819 151617181920 161718192021", "abcdefghijklmnopqrstuvwxyz", "1 2.0 testtest", "".join(["printf %s " % num for num in range(NUM_PRINTFS)])]

if len(sys.argv) > 1:
    funcs = sys.argv[1:]
    pairs = filter(lambda p: p[0] in funcs, zip(tests, results))
else:
    pairs = zip(tests, results)

for test, res in pairs:
    sub = subprocess.Popen([ENERGY_MEASURE, TEST_PROG, test], stdout=PIPE, stderr=PIPE, stdin=PIPE)
    
    outdata, errdata = sub.communicate()
    if outdata.split("\n")[0] == res:
        print "%s test was successful" % test
    else:
        print "%s test was unsuccessful (expected %s, got %s)" % (test, res, outdata.split("\n")[0])

    with open("output-%s.txt" % test, "w") as f:
        f.write(outdata)
    with open("error-%s.txt" % test, "w") as f:
        f.write(errdata)

    time.sleep(0.25)
#        print "disabler stderr:"
#        for line in disabler.stderr:
#            print line
#
#        print "~~~"
#        print "analyzer stderr:"
#        for line in sub.stderr:
#            print line
