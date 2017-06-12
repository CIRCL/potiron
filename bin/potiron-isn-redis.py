#!/usr/bin/env python3

import subprocess
import argparse
import json
import redis
import sys
import os
import potiron
import datetime


non_index = ['', 'timestamp', 'state', 'type']
bpf_filter = potiron.isn_tshark_filter


def store_packet(rootdir, pcapfilename, obj):
    if rootdir is not None:
        jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
        with open(jsonfilename, "w") as f:
            f.write(obj)
        potiron.infomsg("Created filename " + jsonfilename)
        return jsonfilename
    else:
        sys.stdout.write(obj)


def create_dirs(rootdir, pcapfilename):
    jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
    d = os.path.dirname(jsonfilename)
    if not os.path.exists(d):
        os.makedirs(d)


def process_file(outputdir, filename):
    if not potiron.check_program("tshark"):
        raise OSError("The program tshark is not installed")
    sensorname = potiron.derive_sensor_name(filename)
    revcreated = False
    lastday = None
    local_dicts = dict()
    rev_dics = dict()
    allpackets = []
    # Describe the source
    allpackets.append({"type": potiron.TYPE_SOURCE, "sensorname": sensorname,
                       "filename": os.path.basename(filename)})
    # Each packet as a incremental numeric id
    # A packet is identified with its sensorname filename and packet id for
    # further aggregation with meta data.
    # Assumption: Each program process the pcap file the same way?
    packet_id = 0
    cmd = "tshark -n -q -Tfields -e frame.time_epoch -e tcp.srcport -e tcp.dstport -e tcp.seq -e tcp.ack "
    cmd += "-E header=n -E separator=/s -E occurrence=f -Y '{}' -r {} -o tcp.relative_sequence_numbers:FALSE".format(bpf_filter, filename)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    for line in proc.stdout.readlines():
        packet_id = packet_id + 1
        line = line[:-1].decode()
        timestamp, sport, dport, tcpseq, tcpack = line.split(' ')
        isport = -1
        idport = -1
        itcpseq = -1
        itcpack = -1
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
        # Convert timestamp
        a, b = timestamp.split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
        stime = stime + "." + b[:-3]
        packet = {'timestamp': stime,
                  'sport': isport,
                  'dport': idport,
                  'tcpseq': itcpseq,
                  'tcpack': itcpack,
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
        p = red.pipeline()
        for k in packet:
            if k not in non_index:
                feature = packet[k]
                if k.startswith(potiron.ANNOTATION_PREFIX):
                    feature = potiron.translate_dictionaries(rev_dics, red, k, packet[k])
                    # Create the links between annotations and their objects
                    idn = potiron.get_dictionary_id(k)
                    obj = potiron.get_annotation_origin(packet, k)
                    if obj is not None and idn is not None:
                        kn = "AR_{}_{}".format(idn, obj)
                        p.set(kn, feature)
                keyname = "{}_{}".format(sensorname,timestamp)
                p.hset(keyname,k,feature)
        p.execute()
    proc.wait()
    if proc.returncode != 0:
        errmsg = b"".join(proc.stderr.readlines())
        raise OSError("tshark failed. Return code {}. {}".format(proc.returncode, errmsg))
    store_packet(outputdir, filename, json.dumps(allpackets))
        

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Start the tool tshark and store data into a json document and redis in the same time')
    parser.add_argument('-i', '--filename', type=str, nargs=1, help='Pcap or compressed pcap filename.')
    parser.add_argument('-u', '--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-o', '--output', type=str, nargs=1, help='Json output file')
    parser.add_argument("-bf", "--bpffilter", type=str, nargs='+', help="BPF Filter")
    parser.add_argument('--reverse', action='store_false', help='Create global reverse dictionaries')
    args = parser.parse_args()
    
    if args.unix is None:
        sys.stderr.write('A unix socket must be specified\n')
        sys.exit(1)
    
    usocket = args.unix[0]
    
    red = redis.Redis(unix_socket_path=usocket)
    
    if not args.reverse:
        potiron.create_reverse_global_dicts(red)
        potiron.infomsg("Created global reverse annotation dictionaries")
        sys.exit(0)
    
    if args.filename is None:
        sys.stderr.write('A filename must be specified\n')
        sys.exit(1)
    filename = args.filename[0]
    
    if args.bpffilter is not None:
        if len(args.bpffilter) == 1:
            bpffilter = args.bpffilter[0]
            bpf_filter += " && {}".format(bpffilter)
        else:
            sys.stderr.write("Due to the possibility your filter contains '|' caracter, it should be defined between simple or double quotes.\n")
            sys.exit(1)
    
#    # Check if file was already imported
#    fn = os.path.basename(filename)
#    if red.sismember("FILES", fn):
#        sys.stderr.write('[INFO] Filename {} was already imported ... skip ...\n'.format(fn))
#        sys.exit(0)
#    red.sadd("FILES", fn)
    
    if args.output is not None and os.path.isdir(args.output[0]) is False:
        if not os.path.exists(args.output[0]):
            create_dirs(args.output[0], filename)
        else:
            sys.stderr.write("The output you specified is not a directory\n")
            sys.exit(1)
    
    try:
        outputdir = None
        if args.output is None:
            sys.stderr.write('An output directory must be specified\n')
        else:
            outputdir = args.output[0]
        process_file(outputdir, filename)
    except OSError as e:
        sys.stderr.write("A processing error happend.{}.\n".format(e))
        sys.exit(1)
                