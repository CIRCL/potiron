#!/usr/bin/env python3
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2017 Christian Studer
#    Copyright (C) 2017 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
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
import redis
import datetime


def process_file(outputdir, inputfile):
    # If tshark is not installed, exit and raise the error
    if not potiron.check_program("tshark"):
        raise OSError("The program tshark is not installed")
    # Name of the honeypot
    sensorname = potiron.derive_sensor_name(inputfile)
    revcreated = False
    lastday = None
    local_dicts = dict()
    rev_dics = dict()
    allpackets = []
    # Describe the source
    allpackets.append({"type": potiron.TYPE_SOURCE, "sensorname": sensorname,
                       "filename": os.path.basename(inputfile)})
    # Each packet has a incremental numeric id
    # A packet is identified with its sensorname filename and packet id for
    # further aggregation with meta data.
    # Assumption: Each program process the pcap file the same way?
    packet_id = 0
    timestampKey = None
    cmd = "tshark -n -q -Tfields -e frame.time_epoch -e eth.src -e eth.dst -e arp.src.proto_ipv4 -e arp.dst.proto_ipv4 -e arp.src.hw_mac "
    cmd += "-e arp.dst.hw_mac -e arp.opcode -E header=n -E separator='|' -Y 'eth.type == 0x806' -r {}".format(inputfile)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in proc.stdout.readlines():
        packet_id = packet_id + 1
        line = line[:-1].decode()
        timestamp, ethsrc, ethdst, ipsrc, ipdst, arpsrc, arpdst, opcode = line.split('|')
        # Convert timestamp
        a, b = timestamp.split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
        stime += ".{}".format(b[:-3])
        packet = {'timestamp': stime,
                  'ethsrc': ethsrc,
                  'ethdst': ethdst,
                  'ipsrc': ipsrc,
                  'ipdst': ipdst,
                  'arpsrc': arpsrc,
                  'arpdst': arpdst,
                  'opcode': opcode,
                  'type': potiron.TYPE_PACKET,
                  'state': potiron.STATE_NOT_ANNOTATE
                  }
        allpackets.append(packet)
        if not revcreated:
            # FIXME if a json file was annotated twice the resulting json file
            # includes two dictionaries of the same type
            # Only the last one is considered
            rev_dics = potiron.create_reverse_local_dicts(local_dicts)
            revcreated = True
        (day, time) = stime.split(' ')
        timestamp = "{}_{}".format(day,time)
        day = day.replace('-', '')
        if day != lastday:
            red.sadd("DAYS", day)
        # Store data into redis
        p = red.pipeline()
        countKeyname = '{}_{}_count'.format(sensorname,day)
        if opcode == '1':
            keyname = '{}_{}_{}'.format(sensorname, ipdst, timestamp)
#            print(keyname)
            p.hset(keyname, 'req_src_mac', ethsrc)
            p.hset(keyname, 'req_src_ip', ipsrc)
            p.hset(keyname, 'req_src_arp_mac', arpsrc)
            p.zincrby(countKeyname, 'request', 1)
            timestampKey = timestamp
        else:
            keyname = '{}_{}_{}'.format(sensorname, ipsrc, timestampKey)
#            print(keyname)
            p.hset(keyname, 'rep_timestamp', stime)
            p.hset(keyname, 'rep_dst_ip', ipdst)
            p.hset(keyname, 'rep_src_mac', ethsrc)
            p.hset(keyname, 'rep_dst_mac', ethdst)
            p.hset(keyname, 'rep_src_arp_mac', arpsrc)
            p.hset(keyname, 'rep_dst_arp_mac', arpdst)
            p.zincrby(countKeyname, 'reply', 1)
        p.execute()
    proc.wait()
    if proc.returncode != 0:
        errmsg = b"".join(proc.stderr.readlines())
        raise OSError("tshark failed. Return code {}. {}".format(proc.returncode, errmsg))
    # Write data into the json output file
    potiron.store_packet(outputdir, inputfile, json.dumps(allpackets))


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Start the tool tshark and transform the output in a json document")
    parser.add_argument('-i', '--input', type=str, nargs=1, help='Pcap or compressed pcap filename')
    parser.add_argument('-c', '--console', action='store_true', help='Log output also to console')
    parser.add_argument('-o', '--outputdir', type=str, nargs=1, help='Output directory where the json documents will be stored')
    parser.add_argument('-u', '--unix', type=str, nargs=1, help='Unix socket to connect to redis-server')
    args = parser.parse_args()
    potiron.logconsole = args.console
    
    if args.input is None:
        sys.stderr.write("At least a pcap file must be specified\n")
        sys.exit(1)
    else:
        if os.path.exists(args.input[0]) is False:
            sys.stderr.write("The filename {} was not found\n".format(args.input[0]))
            sys.exit(1)
        inputfile = args.input[0]
    
    if args.unix is None:
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    
    if args.outputdir is None:
        sys.stderr.write("You should specify an output directory.\n")
        sys.exit(1)
    else:
        rootdir = args.outputdir[0]
        potiron.create_dirs(rootdir, inputfile)
        if os.path.isdir(rootdir) is False:
            sys.stderr.write("The root directory is not a directory\n")
            sys.exit(1)
    
    # Check if file was already imported
    fn = os.path.basename(inputfile)
    fn = '{}.json'.format(fn.split('.')[0])
    if red.sismember("FILES", fn):
        sys.stderr.write('[INFO] Filename {} was already imported ... skip ...\n'.format(fn))
        sys.exit(0)
    red.sadd("FILES", fn)        
    
    process_file(rootdir, inputfile)
