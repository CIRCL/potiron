#!/usr/bin/python
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
import getopt
import sys
import potiron
from potiron import errormsg
from potiron import infomsg
from potiron import check_program
import datetime

def usage():
    print """potiron-json-ipsumpdump.py [-h] [-r filename]  [-d directory] [-k]

    -h              Shows this screen
    -d directory    Specify the directory where the files should be stored
    -r filename     Specify the pcap filename that should be dissected by
                    ipsumdump
    -k              Log data also sent to console and not only to syslog
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

"""

def numerize_proto(pstr):
    if pstr=="I":
        return potiron.PROTO_ICMP
    elif pstr == "T":
        return potiron.PROTO_TCP
    elif pstr == "U":
        return potiron.PROTO_UDP
    elif pstr =="41":
        return potiron.PROTO_ICMP6
    elif pstr =="-":
        #Avoid error messages when protocol is not set
        return potiron.PROTO_UNKNOWN
    #If there is a protocol number return it
    try:
        return int(pstr)
    except ValueError:
        errormsg("Unknown protocol "+pstr)
        return potiron.PROTO_UNKNOWN
    #Should not be executed
    return potiron.PROTO_UNKNOWN

def store_packet(rootdir, pcapfilename, obj):
    jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
    f = open(jsonfilename,"w")
    f.write(obj)
    f.close()
    infomsg("Created filename "+jsonfilename)

def create_dirs(rootdir, pcapfilename):
    jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
    d = os.path.dirname(jsonfilename)
    if os.path.exists(d) == False:
        os.makedirs(d)

def process_file(rootdir, filename):
    if check_program("ipsumdump") == False:
        raise OSError("The program ipsumpdump is not installed")
    #FIXME Put in config file
    create_dirs(rootdir, filename)
    packet = {}
    sensorname = potiron.derive_sensor_name(filename)
    allpackets = []
    #Each packet as a incremental numeric id
    #A packet is identified with its sensorname filename and packet id for
    #further aggregation with meta data.
    #Assumption: Each program process the pcap file the same way?
    packet_id = 0
    proc = subprocess.Popen(["ipsumdump","--no-headers","--quiet","--timestamp",
    "--length","--protocol","--ip-src","--ip-dst","--ip-opt","--ip-ttl","--ip-tos",
    "--sport","--dport","--icmp-code","--icmp-type",
    "-f",potiron.bpffilter, "-r", filename], stdout=subprocess.PIPE,
         stderr=subprocess.PIPE)
    for line in proc.stdout.readlines():
        packet_id = packet_id + 1
        line = line[:-1]
        (timestamp, length,  protocol, ipsrc, ipdst, ipop, ipttl, iptos,
        sport, dport, icmpcode, icmptype) = line.split(' ')
        ilength = -1
        iipttl = -1
        iiptos = -1
        isport = -1
        idport = -1
        iicmpcode = 255
        iicmptype = 255
        try:
            ilength = int(length)
            iipttl = int(ipttl)
            iiptos = int(iptos)
            isport = int(sport)
            idport = int(dport)
            iicmpcode = int(iicmpcode)
            iicmptype = int(iicmptype)
        except ValueError:
            pass
        if ipsrc == '-':
            ipsrc = None
        if ipdst == '-':
            ipdst = None
        #Convert timestamp
        (a,b) = timestamp.split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
        stime = stime + "." + b

        packet = { 'timestamp' : stime,
                   'length' : ilength,
                   'protocol': numerize_proto(protocol),
                  'ipsrc': ipsrc,
                  'ipdst': ipdst,
                  'ipop':  ipop,
                 'ipttl': iipttl,
                 'iptos': iiptos,
                 'sport': isport,
                 'dport': idport,
                 'icmpcode': iicmpcode,
                 'icmptype': iicmptype,
                 'sensorname': sensorname,
                 'packet_id' : packet_id,
                 'filename': os.path.basename(filename),
                    };
        #FIXME might consume a lot of memory
        allpackets.append(packet)

    #FIXME Implement polling because wait can last forever
    proc.wait()

    if proc.returncode != 0:
        errmsg = "".join(proc.stderr.readlines())
        raise OSError("ipsumdump failed. Return code "+str(proc.returncode)
                      + ". " + errmsg)
    store_packet(rootdir, filename, json.dumps(allpackets))



if __name__ == '__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hr:d:k")
    except getopt.GetoptError as err:
        usage()
        sys.exit(1)

    filename = None
    rootdir = None
    output = None
    verbose = False
    for o, a in opts:
        if o == "-h":
            usage()
            sys.exit(0)
        elif o == "-r":
            filename = a
        elif o == "-d":
            rootdir = a
        elif o == "-k":
            potiron.logconsole = True
        else:
            sys.exit(1)

    if filename is None:
        errormsg("A filename must be specified")
        sys.exit(1)

    if os.path.exists(filename) is False:
        errormsg("The filename " + filename + " was not found")
        sys.exit(1)

    if rootdir is None:
        errormsg("The root directory was not specified")
        sys.exit(1)

    if os.path.isdir(rootdir) is False:
        errormsg("The root directory is not a directory")
        sys.exit(1)

    try:
        process_file(rootdir, filename)
    except OSError,e:
        errormsg("A processing error happend."+str(e)+".\n")
        sys.exit(1)
