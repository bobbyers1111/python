#!/usr/bin/python

#   +----------+
#---| netmonpy |---------------------------------------------------------------
#   +----------+

"""
SCRIPT: netmonpy.py
AUTHOR: bob byers
(C) 2016

This script is a very simplistic network monitoring tool. It is
designed more as a vehicle for learning python than as a
production-ready script.

When invoked, the script enters a loop which performs the
following:

1) Obtain current interface statistics for all interfaces

2) Compute deltas for each stat and its corresponding stat from
the previous iteration

3) If any of the stats exceed some threshold, spawn an instance of
wireshak, collecting traffic for a brief time, saving the packets
to disk and displaying conversation and protocol summaries. The
captured packets are left on disk for later analysis.

4) sleep a pre-determined abount of time and repeat the loop

Currently there is no mechanism for gracefully exiting the loop.
Suggested workaround is Ctrl-C to terminate the program.
"""
#------------------------------------------------------------------------------

import re
import time
import subprocess as sp
from datetime import datetime
from datetime import timedelta

STATSFILE = '/proc/net/dev'

#-- Is there a way to put this inside a function and still make it readable?

parseIpStats = re.compile("^\
(?P<srcip>\d+\.\d+\.\d+\.\d+)\s+<->\s+\
(?P<dstip>\d+\.\d+\.\d+\.\d+)\s+\
(?P<rxframes>\d+)\s+\
(?P<rxbytes>\d+)\s+\
(?P<txframes>\d+)\s+\
(?P<txbytes>\d+)\s+\
(?P<totframes>\d+)\s+\
(?P<totbytes>\d+)\s+\
(?P<relstart>\S+)\s+\
(?P<duration>\S+)\s*$")

#   +-------+
#---| touch |------------------------------------------------------
#   +-------+
#
# Like /bin/touch, but not quite as mature ;)

def touch(file):
    open(file, 'a').close()

#   +--------------+
#---| run_capinfos |----------------------------------------------
#   +--------------+
#
# Spawns wireshark's capinfos utility, which we use to display an
# overall summary of the pcap file (packets, duration, etc.)
#
# ARGS
#   pcapfile	Name of a PCAP file
#
# RETURNS
#   <nothing>
#-----------------------------------------------------------------

def run_capinfos(pcapfile):

  #-- Location of the capinfos executable, and desired options

      capinfos_exe = '/usr/sbin/capinfos'
      capinfos_options = '-cmuxy'

  #-- Spawn capinfos

      child = sp.Popen([capinfos_exe, capinfos_options, pcapfile], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

      outbuf = ''
      for line in child.stdout:
        outbuf += line

      streamdata = child.communicate()[0]
      rc = child.returncode

      if rc != 0:
        print '     WARNING: capinfos returned non-zero status:',rc

      for line in outbuf.split('\n'):
        print '    ', line.strip()

#   +-------------+
#---| interesting |-----------------------------------------------
#   +-------------+
#
# Returns True if a line contains something we care about.
#
# TO DO:
#
# Make regular expressions more stringent.
#
# Parse actual values to do integer comparisons (rather than
# counting spaces between fields)

def interesting(line):

  #-- Threshold 

      THRESH_totframes = 25

  #-- Ignore Eth conversations with too few frames
      if re.search("^..:..:..:..:..:..    .-. ..:..:..:..:..:..          .", line):
        return False

  #-- Ignore IP conversations with too few frames

      parsed = re.search(parseIpStats, line)

      if parsed:
        if int(parsed.group('totframes')) <= THRESH_totframes:
          return False

  #-- Ignore the filter report from tshark, it has no interest to us

      if re.search("^Filter:.No Filter.", line):
        return False

  #-- If we get this far the line must be interesting

      return True

#   +------------------+
#---| uty_capsummaries |------------------------------------------
#   +------------------+
#
# Display a summary of top conversations for traffic of a 
#particular category
#
#   -----        ----------------------------
#   categ	 Meaning
#   -----        ----------------------------
#    eth         MAC Addresses conversations
#    ip          IP Address conversations
#
#-----------------------------------------------------------------

def uty_capsummaries(pcapfile, categ):

    child = sp.Popen([ '/usr/sbin/tshark', categ, '-nqr', pcapfile ], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

    outbuf = ''
    for line in child.stdout:
      outbuf += line

    streamdata = child.communicate()[0]
    rc = child.returncode

    if rc != 0:
      print 'WARNING: tshark -zconv, '+categ+' returned non-zero status:',rc

    for line in outbuf.split('\n'):
      #Only display data that is of interest to us
      if interesting(line):
        print line.strip()

#   +-----------------+
#---| do_capsummaries |-------------------------------------------
#   +-----------------+
#
# Does tshark summaries for several categories

def do_capsummaries(pcapfile):

    uty_capsummaries(pcapfile, '-zconv,eth')
    uty_capsummaries(pcapfile, '-zconv,ip')
    uty_capsummaries(pcapfile, '-zio,phs')

#   +-----------+
#---| do_tshark |-------------------------------------------------
#   +-----------+
#
# This function spawns an instance of tshark which collects packets on a
# particular interface for a period of time, saving the results to disk for
# later analysis.

def do_tshark(iface,duration):

    OUTDIR = 'PCAPS'
    MAX_PKTS   =  1000000
    MAX_FILESZ = 10000000

    now = datetime.now()
    OUTFILE = "%s/tsharkout_%s_%s.pcap" % (OUTDIR, iface, now.strftime('%Y-%m%d-%H%M%S'))

    #-- Create the pcap file as regular user (otherwise only root can read it)
    touch(OUTFILE)

    #-- Run tshark
    child = sp.Popen([ '/usr/bin/sudo', '/usr/sbin/tshark', '-qn',
     '-i'+iface, '-c'+str(MAX_PKTS), '-aduration:'+str(duration),
     '-afilesize:'+str(MAX_FILESZ), '-w'+OUTFILE ], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

    streamdata = child.communicate()[0]
    rc = child.returncode

    if rc == 0:
      run_capinfos(OUTFILE)
      do_capsummaries(OUTFILE)

    else:
      print 'WARNING: tshark returned non-zero status:', rc

#   +----------+
#---| getstats |--------------------------------------------------
#   +----------+

def getstats():

  stats = {}

  FH = open(STATSFILE, 'r')

  for line in FH:

    line = line.strip()

    if line != "":

      groups = re.match("^([^:]+)\s*:\s*(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$", line)

      if groups:

        iface = groups.group(1)

        stats[iface] = {
         'rxbytes' : groups.group(2),
         'rxpkts' : groups.group(3),
         'rxerrs' : groups.group(4),
         'rxdrop' : groups.group(5),
         'rxfifo' : groups.group(6),
         'rxframe' : groups.group(7),
         'rxcompressed' : groups.group(8),
         'rxmulticast' : groups.group(9),
         'txbytes' : groups.group(10),
         'txpackets' : groups.group(11),
         'txerrs' : groups.group(12),
         'txdrop' : groups.group(13),
         'txfifo' : groups.group(14),
         'txcolls' : groups.group(15),
         'txcarrier' : groups.group(16),
         'txcompressed' : groups.group(17)
        }

  FH.close()

  return stats

#   +-------------+
#---| check_stats |-----------------------------------------------
#   +-------------+

def check_stats(prevstats, stats, direction, capifs):

    print
    print '==',direction.upper()

    THRESH = 1000000

    for iface in sorted(stats):

      for key in stats[iface].keys():

        if re.search(direction, key, re.IGNORECASE):

          diff = int(stats[iface][key]) - int(prevstats[iface][key])

          if diff >= 10:
            print '%4s %13s : %20s - %20s = %d' % (iface, key, stats[iface][key], prevstats[iface][key], diff)

          if diff > THRESH:
            capifs.add(iface)

#   +------+
#---| MAIN |------------------------------------------------------
#   +------+

first = True

while True:

  stats = getstats()

  if first:
    first = False

  else:

    print
    print '='*64
    print '===', datetime.now().strftime('%Y-%m%d-%H:%M:%S')

    capifs = set()

    check_stats(prevstats, stats, 'rx', capifs)
    check_stats(prevstats, stats, 'tx', capifs)

    for iface in capifs:
      do_tshark(iface,4)

  prevstats = stats
  time.sleep(10)
