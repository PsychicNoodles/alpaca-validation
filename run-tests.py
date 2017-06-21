import subprocess
from subprocess import PIPE
import sys
import os

TEST_PROG = "test-suite"
tests = ["bool", "short", "int", "long", "long_long", "float", "double", "int_struct", "double_struct", "two_int", "two_float", "mixed", "eight_int", "everything", "pointer", "triple_double", "global_write", "param_float", "local"]
results = ["1", "2", "3", "4", "5", "6.0", "7.0", "8", "9.0", "10 11", "12.0 13.0", "14 15 16.0", "17 18 19 20 21 22 23 24", "1 24 25 26 27 28.0 29.0", "30 31.0 testtest", "32.0 33.0 34.0", "1 2.0 testtest", "9.3", "2"]

os.environ["LD_PRELOAD"] = "./alpaca.so:libelf++.so:libudis86.so"

if len(sys.argv) > 1:
    funcs = sys.argv[1:]
    pairs = filter(lambda p: p[0] in funcs, zip(tests, results))
else:
    pairs = zip(tests, results)

for test, res in pairs:
    sub = subprocess.Popen([TEST_PROG, test, test + "_func", "analyze"], stdout=PIPE, stderr=PIPE)
    sub.communicate()
    disabler = subprocess.Popen([TEST_PROG, test, test + "_func", "disable"], stdout=PIPE, stderr=PIPE)
    outdata, errdata = disabler.communicate()
    if outdata == res:
        print "%s test was successful" % test
    else:
        print "%s test was unsuccessful (expected %s, got %s)" % (test, res, outdata)
#        print "disabler stderr:"
#        for line in disabler.stderr:
#            print line
#
#        print "~~~"
#        print "analyzer stderr:"
#        for line in sub.stderr:
#            print line
