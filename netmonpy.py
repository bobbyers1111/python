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

2) Compute deltas for each stat with its corresponding stat
from previous iteration

3) If any stat exceeds some threshold, spawn an instance of
wireshak, collecting traffic for a brief time, saving the packets
to disk and displaying conversation and protocol summaries. The
captured packets are left on disk for later analysis.

4) sleep briefly and repeat the loop

Use Ctrl-C to terminate the program.

---- LIMITATIONS --------------------

Assumes a linux system with /proc/net/dev

Assumes wireshark is installed with its companion
utilities (tshark and capinfos).

Assumes tshark can be run by root via sudo WITHOUT password.

---- INTERESTING PYTHON FEATURES ----

1. Uses compiled regular expressions with named fields and
   re.VERBOSE (to make the expression more readable).

2. Spawns and communicates with child processes.

"""
#------------------------------------------------------------------------------

import re
import time
import subprocess as sp
from datetime import datetime
from datetime import timedelta

STATSFILE = '/proc/net/dev'

#   +-------+
#---| touch |------------------------------------------------------
#   +-------+
#
# Like /bin/touch, but not really ;). I need this to insure the
# pcap file is owned by my uid, not root.

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
# Examines a single line from the output of 'tshark -zconv,ip' or
# 'tshark -zconv,eth'
#
# Returns True if the line contains something we care about (e.g.,
# an IP conversation or a MAC conversation). Such lines get a
# return value of True.
#
# In addition, the total frame count of any stat must exceed a
# threshold in order to be considered 'interesting'
#
# Anything else (e.g., blank lines, headers, etc.) are deemed
# not 'interesting' and get a return value of False.

def interesting(line):

  #-- Lines with total frame count under this
  #-- threshold are deemed 'uninteresting'

      THRESH_minframes = 50

  #-- regexes for parsing tshark -zconv, output ----

      parseEthStats = re.compile(
      '''
        ## This parses Ethernet MAC stats from 'tshark -zconv,eth'

          (?P<srcmac>[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\s+
          <->\s+    # Literally, the string '<->'
          (?P<dstmac>[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2}:[0-9a-fA-F]{2})\s+
          (?P<rxframes>\d+)\s+
          (?P<rxbytes>\d+)\s+
          (?P<txframes>\d+)\s+
          (?P<txbytes>\d+)\s+
          (?P<totframes>\d+)\s+
          (?P<totbytes>\d+)\s+
          (?P<relstart>\S+)\s+
          (?P<duration>\S+)\s*$
      ''',
      re.VERBOSE)

      parseIpStats = re.compile(
      """
        ## This parses IP stats from 'tshark -zconv,ip'

          (?P<srcip>\d+\.\d+\.\d+\.\d+)\s+
          <->\s+    # Literally, the string '<->'
          (?P<dstip>\d+\.\d+\.\d+\.\d+)\s+
          (?P<rxframes>\d+)\s+
          (?P<rxbytes>\d+)\s+
          (?P<txframes>\d+)\s+
          (?P<txbytes>\d+)\s+
          (?P<totframes>\d+)\s+
          (?P<totbytes>\d+)\s+
          (?P<relstart>\S+)\s+
          (?P<duration>\S+)\s*$
      """,
      re.VERBOSE)

  #-- Check if this line is an Eth conversation stat

      parsed = re.search(parseEthStats, line)

      if parsed:
        if int(parsed.group('totframes')) <= THRESH_minframes:
          return False
        else:
          return True

  #-- Check if this line is an IP conversation stat

      parsed = re.search(parseIpStats, line)

      if parsed:
        if int(parsed.group('totframes')) <= THRESH_minframes:
          return False
        else:
          return True

  #-- If we get this far the line is not interesting

      return False

#   +------------------+
#---| uty_capsummaries |------------------------------------------
#   +------------------+
#
# Invokes tshark on an existing capture file, using the '-z'
# statistics feature to generate summaries of the traffic.
#
# The caller supplies the name of the pcapfile as well as the
# -z options to pass to tshark.
#
# ARGs
#
#     pcapfile       Name of the PCAP file
#
#     zopt           The '-z' option to pass on to tshark. This
#                    must be a valid option for tshark. The '-z'
#                    should be included as well. Examples:
#
#     ----         ---------------------------
#     zopt	   Meaning
#     ----         ---------------------------
#    -zconv,eth   Summarize all Ethernet conversations
#    -zconv,ip    Summarize all IP conversations
#    -zio,phs     Produce a protocol hierarchy report
#
# TO DO:
#
#   Currently there is no validation of the zopt passed in from
#   the caller. We blindly pass zopt on to tshark. 
#
#-----------------------------------------------------------------

def uty_capsummaries(pcapfile, zopt):

  #-- Spawn tshark

    child = sp.Popen([ '/usr/sbin/tshark', zopt, '-nqr', pcapfile ], shell=False, stdout=sp.PIPE, stderr=sp.PIPE)

  #-- Collect its output

    outbuf = ''
    for line in child.stdout:
      outbuf += line

    streamdata = child.communicate()[0]
    rc = child.returncode

  #-- Check tshark exit status

    if rc != 0:
      print 'WARNING: tshark -zconv, '+zopt+' returned non-zero status:',rc

  #-- Display the tshark output

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
#
# LIMITATION:
#
# This was developed on a system that 1) only allows tshark to capture
# packets as root, and 2) sudoers is configured such that tshark can
# be run as root by the current user without entering a password.
#
# TO DO:
# Create the ouptut directory if it doesn't already exist

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
#
# Interface stats on a linux system can be obtained simply by reading
# the file /proc/net/dev. Results for all interfaces are returned.
#
# This function opens that file, reads in its data, parses the data
# line-by-line, stores the data in a two-dimensional list (each row
# has data for one interface, stored as a dictionary structure)
#
# RETURNS:
#   Returns the 2D statistics data structure. 

def getstats():

  regex_procNetDev = re.compile(
    '''^\s*
    ## This regex is used to parse a data line read from /proc/net/dev
       ^\s*
       (?P<iface>[^:]+):\s+         # Interface name, terminated by ':'
       (?P<rxbytes>\d+)\s+
       (?P<rxpkts>\d+)\s+
       (?P<rxerrs>\d+)\s+
       (?P<rxdrop>\d+)\s+
       (?P<rxfifo>\d+)\s+
       (?P<rxframe>\d+)\s+
       (?P<rxcompressed>\d+)\s+
       (?P<rxmulticast>\d+)\s+
       (?P<txbytes>\d+)\s+
       (?P<txpackets>\d+)\s+
       (?P<txerrs>\d+)\s+
       (?P<txdrop>\d+)\s+
       (?P<txfifo>\d+)\s+
       (?P<txcolls>\d+)\s+
       (?P<txcarrier>\d+)\s+
       (?P<txcompressed>\d+)
       \s*$
    ''',
    re.VERBOSE)

  stats = {}

  FH = open(STATSFILE, 'r')

  for line in FH:

    if line.strip() != "":

      parsed = re.match(regex_procNetDev, line)

      if parsed:

        iface = parsed.group('iface')

        #-- Each row of the stats table contains all
        #-- stats for one interface, stored as a dictionary

        stats[iface] = {
         'rxbytes' : parsed.group('rxbytes'),
         'rxpkts' : parsed.group('rxpkts'),
         'rxerrs' : parsed.group('rxerrs'),
         'rxdrop' : parsed.group('rxdrop'),
         'rxfifo' : parsed.group('rxfifo'),
         'rxframe' : parsed.group('rxframe'),
         'rxcompressed' : parsed.group('rxcompressed'),
         'rxmulticast' : parsed.group('rxmulticast'),
         'txbytes' : parsed.group('txbytes'),
         'txpackets' : parsed.group('txpackets'),
         'txerrs' : parsed.group('txerrs'),
         'txdrop' : parsed.group('txdrop'),
         'txfifo' : parsed.group('txfifo'),
         'txcolls' : parsed.group('txcolls'),
         'txcarrier' : parsed.group('txcarrier'),
         'txcompressed' : parsed.group('txcompressed')
        }

  FH.close()

  return stats

#   +-------------+
#---| check_stats |-----------------------------------------------
#   +-------------+

def check_stats(prevstats, stats, direction, capifs):

    print
    print '==',direction.upper()

    #-- Threshold for triggering a print statement
    THRESH_forprint = 10

    #-- Threshold for triggering a packet capture
    THRESH_forcapture = 1000000

    for iface in sorted(stats):

      for key in stats[iface].keys():

        if re.search(direction, key, re.IGNORECASE):

          diff = int(stats[iface][key]) - int(prevstats[iface][key])

          if diff >= THRESH_forprint:
            print '%4s %13s : %20s - %20s = %d' % (iface, key, stats[iface][key], prevstats[iface][key], diff)

          if diff > THRESH_forcapture:
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
