#!/usr/bin/env python3
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2014 Gerard Wagener
#    Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.


import subprocess
import os
import json
import sys
import potiron
import argparse
from potiron import errormsg
from potiron import infomsg
from potiron import check_program
import datetime


def usage():
    print("""potiron-json-ipsumpdump.py [-h] [-r filename]  [-d directory] [-c]

    -h              Shows this screen
    -o output       Specify the directory where the files should be stored
    -r filename     Specify the pcap filename that should be dissected by
                    ipsumdump
    -c              Log data also sent to console and not only to syslog
                    The filename is specified with the -r option

FILENAME CONVENTION

    The filename must have the format

    prefix-sensorname-instance-date

  EXAMPLE

    lowint-honeypot-1-20140826000000

DATE FORMAT

%Y%m%

JSON DOCUMENT STORE

The json files are stored in the root directory specified with the -d option.
In order to not overwhelm the directory with files and to find them quickly
back the following sub-directory structure is created.

sensorname/year/month/day/filename

EXAMPLE

    document-root/honeypot-1/2014/08/26/lowint-honeypot-1-20140826


If no DOCUMENT STORE directory is specified the json object is written
on standard output
""")


def numerize_proto(pstr):
    if pstr == "I":
        return potiron.PROTO_ICMP
    elif pstr == "T":
        return potiron.PROTO_TCP
    elif pstr == "U":
        return potiron.PROTO_UDP
    elif pstr == "41":
        return potiron.PROTO_ICMP6
    elif pstr == "-":
        # Avoid error messages when protocol is not set
        return potiron.PROTO_UNKNOWN
    # If there is a protocol number return it
    try:
        return int(pstr)
    except ValueError:
        errormsg("Unknown protocol " + pstr)
        return potiron.PROTO_UNKNOWN
    # Should not be executed
    return potiron.PROTO_UNKNOWN


def store_packet(rootdir, pcapfilename, obj):
    if rootdir is not None:
        jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
        with open(jsonfilename, "w") as f:
            f.write(obj)
        infomsg("Created filename " + jsonfilename)
    else:
        sys.stdout.write(obj)


def create_dirs(rootdir, pcapfilename):
    jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
    d = os.path.dirname(jsonfilename)
    if not os.path.exists(d):
        os.makedirs(d)


def process_file(rootdir, filename):
    if not check_program("ipsumdump"):
        raise OSError("The program ipsumpdump is not installed")
    # FIXME Put in config file
    if rootdir is not None:
        create_dirs(rootdir, filename)
    packet = {}
    sensorname = potiron.derive_sensor_name(filename)
    allpackets = []
    # Describe the source
    allpackets.append({"type": potiron.TYPE_SOURCE, "sensorname": sensorname,
                       "filename": os.path.basename(filename)})
    # Each packet as a incremental numeric id
    # A packet is identified with its sensorname filename and packet id for
    # further aggregation with meta data.
    # Assumption: Each program process the pcap file the same way?
    packet_id = 0
    proc = subprocess.Popen(["ipsumdump", "--no-headers", "--quiet", "--timestamp",
                             "--length", "--protocol", "--ip-src", "--ip-dst", "--ip-opt",
                             "--ip-ttl", "--ip-tos", "--sport", "--dport", "--tcp-seq", "--tcp-ack",
                             "--icmp-code", "--icmp-type", "-f", potiron.bpffilter, "-r", filename], 
                             stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in proc.stdout.readlines():
        packet_id = packet_id + 1
        line = line[:-1].decode()
        timestamp, length, protocol, ipsrc, ipdst, ipop, ipttl, iptos, sport, dport, tcpseq, tcpack, icmpcode, icmptype = line.split(' ')
        ilength = -1
        iipttl = -1
        iiptos = -1
        isport = -1
        idport = -1
        itcpseq = -1
        itcpack = -1
        iicmpcode = 255
        iicmptype = 255
        try:
            ilength = int(length)
        except ValueError:
            pass
        try:
            iipttl = int(ipttl)
        except ValueError:
            pass
        try:
            iiptos = int(iptos)
        except ValueError:
            pass
        try:
            isport = int(sport)
        except ValueError:
            pass
        try:
            idport = int(dport)
        except ValueError:
            pass
        try:
            itcpseq = int(tcpseq)
        except ValueError:
            pass
        try:
            itcpack = int(tcpack)
        except ValueError:
            pass
        try:
            iicmpcode = int(icmpcode)
        except ValueError:
            pass
        try:
            iicmptype = int(icmptype)
        except ValueError:
            pass
        
        if ipsrc == '-':
            ipsrc = None
        if ipdst == '-':
            ipdst = None
        # Convert timestamp
        a, b = timestamp.split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
        stime = stime + "." + b
        packet = {'timestamp': stime,
                  'length': ilength,
                  'protocol': numerize_proto(protocol),
                  'ipsrc': ipsrc,
                  'ipdst': ipdst,
                  'ipop': ipop,
                  'ipttl': iipttl,
                  'iptos': iiptos,
                  'sport': isport,
                  'dport': idport,
                  'tcpseq': itcpseq,
                  'tcpack': itcpack,
                  'icmpcode': iicmpcode,
                  'icmptype': iicmptype,
                  'packet_id': packet_id,
                  'type': potiron.TYPE_PACKET,
                  'state': potiron.STATE_NOT_ANNOATE
                  }
        # FIXME might consume a lot of memory
        allpackets.append(packet)

    # FIXME Implement polling because wait can last forever
    proc.wait()

    if proc.returncode != 0:
        errmsg = "".join(proc.stderr.readlines())
        raise OSError("ipsumdump failed. Return code {}. {}".format(proc.returncode, errmsg))
    store_packet(rootdir, filename, json.dumps(allpackets))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Start the too ipsumpdump and transform the output in a json document")
    parser.add_argument("-r", "--read", type=str, nargs=1, help="Compressed pcap file or pcap filename")
    parser.add_argument("-c", "--console", action='store_true', help="Log output also to console")
    parser.add_argument("-o", "--directory", nargs=1, help="Output directory where the json documents are stored")

    args = parser.parse_args()
    potiron.logconsole = args.console
    if args.read is not None:
        if os.path.exists(args.read[0]) is False:
            errormsg("The filename {} was not found".format(args.read[0]))
            sys.exit(1)

    if args.directory is not None and os.path.isdir(args.directory[0]) is False:
        errormsg("The root directory is not a directory")
        sys.exit(1)

    if args.read is None:
        errormsg("At least a pcap file must be specified")
        sys.exit(1)
    try:
        rootdir = None
        if args.directory is not None:
            rootdir = args.directory[0]
        process_file(rootdir, args.read[0])
    except OSError as e:
        errormsg("A processing error happend.{}.\n".format(e))
        sys.exit(1)
