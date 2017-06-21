import struct

def read_writes(count, f):
    print "reading from write log"
    finished_line = False
    try:
        for write in range(count):
            dest, val = struct.unpack("QQ", f.read(16))
            print "write %s to %s" % (val, hex(dest))
    except struct.error:
        print "write log ended abruptly"

print "reading from return log"
finished_line = False
try:
    with open("return-logger", "rb") as return_log:
        with open("write-logger", "rb") as write_log:
            while 1:
                write_count = struct.unpack("Q", return_log.read(8))[0]
                print "write_count: %s" % write_count
                if write_count > 0: read_writes(write_count, write_log)
                finished_line = False
                flag = struct.unpack("b", return_log.read(1))[0]
                print "flag: %s" % flag
                if flag & 0b1:
                    print "rax: %s" % struct.unpack("Q", return_log.read(8))
                if flag & 0b10:
                    print "rdx: %s" % struct.unpack("Q", return_log.read(8))
                if flag & 0b100:
                    print "xmm0: %f %f %f %f" % struct.unpack("ffff", return_log.read(16))
                if flag & 0b1000:
                    print "xmm1: %f %f %f %f" % struct.unpack("ffff", return_log.read(16))
                finished_line = True
except struct.error: 
    if finished_line:
        print "finished reading from return log"
    else:
        print "return log ended abruptly"
