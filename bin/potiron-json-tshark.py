#!/usr/bin/env python3


import subprocess
import os
import json
import sys
import potiron
import argparse
import redis
from potiron import infomsg, check_program
import datetime
import potiron_redis
        

bpf_filter = potiron.tshark_filter


# Save the output json file 
def store_packet(rootdir, pcapfilename, obj):
    if rootdir is not None:
        jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
        with open(jsonfilename, "w") as f:
            f.write(obj)
        infomsg("Created filename " + jsonfilename)
        return jsonfilename
    else:
        sys.stdout.write(obj)
        

# Create the output directory and file if it does not exist        
def create_dirs(rootdir, pcapfilename):
    jsonfilename = potiron.get_file_struct(rootdir, pcapfilename)
    d = os.path.dirname(jsonfilename)
    if not os.path.exists(d):
        os.makedirs(d)


# Complete the packet with values that need some verifications
def fill_packet(packet):
    # Convert timestamp
    a, b = packet['timestamp'].split('.')
    dobj = datetime.datetime.fromtimestamp(float(a))
    stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
    stime = stime + "." + b[:-3]
    packet['timestamp'] = stime
    if 'protocol' in packet:
        try:
            protocol = int(packet['protocol'])
            packet['protocol'] = protocol
        except ValueError:
            pass
        sport = -1
        dport = -1
        if packet['protocol'] == 6:
            if 'tsport' in packet:
                sport = packet['tsport']
            if 'tdport' in packet:
                dport = packet['tdport']
        else:
            if 'usport' in packet:
                sport = packet['usport']
            if 'udport' in packet:
                dport = packet['udport']
        if ('tsport' in packet) or ('usport' in packet):
            packet['sport'] = sport
        if ('tdport' in packet) or ('udport' in packet):
            packet['dport'] = dport
        if 'tsport' in packet:
            del packet['tsport']
        if 'usport' in packet:
            del packet['usport']
        if 'tdport' in packet:
            del packet['tdport']
        if 'udport' in packet:
            del packet['udport']
    if 'ipsrc' in packet and packet['ipsrc'] == '-':
        packet['ipsrc'] = None
    if 'ipdst' in packet and packet['ipdst'] == '-':
        packet['ipdst'] = None


# Process data saving into json file and storage into redis
def process_file(rootdir, filename, fieldfilter, b_redis):
    # If tshark is not installed, exit and raise the error
    if not check_program("tshark"):
        raise OSError("The program tshark is not installed")
    # FIXME Put in config file
    # Name of the honeypot
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
    tshark_fields = potiron.tshark_fields
    cmd = "tshark -n -q -Tfields "
    if fieldfilter:
        if 'frame.time_epoch' not in fieldfilter:
            fieldfilter.insert(0, 'frame.time_epoch')
        for p in fieldfilter:
            cmd += "-e {} ".format(p)
    else:
        for f in tshark_fields:
            cmd += "-e {} ".format(f)
    cmd += "-E header=n -E separator=/s -E occurrence=f -Y '{}' -r {} -o tcp.relative_sequence_numbers:FALSE".format(bpf_filter, filename)
    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    json_fields = potiron.json_fields
    special_fields = {'length': -1, 'ipttl': -1, 'iptos': 0, 'tcpseq': -1, 'tcpack': -1, 'icmpcode': 255, 'icmptype': 255}
    for line in proc.stdout.readlines():
        packet_id = packet_id + 1
        line = line[:-1].decode()
        packet = {}
        tab_line = line.split(' ')
        for i in range(len(tab_line)):
            if fieldfilter:
                valname = json_fields[tshark_fields.index(fieldfilter[i])]
            else:
                valname = json_fields[i]
            if valname in special_fields:
                v = special_fields[valname]
                try:
                    v = int(tab_line[i])
                except ValueError:
                    pass
                packet[valname] = v
            else:
                packet[valname] = tab_line[i]
        fill_packet(packet)
        packet['packet_id'] = packet_id
        packet['type'] = potiron.TYPE_PACKET
        packet['state'] = potiron.STATE_NOT_ANNOTATE
        # FIXME might consume a lot of memory
        allpackets.append(packet)

    # FIXME Implement polling because wait can last forever
    proc.wait()

    if proc.returncode != 0:
        errmsg = b"".join(proc.stderr.readlines())
        raise OSError("tshark failed. Return code {}. {}".format(proc.returncode, errmsg))
    # Write and save the json file
    jsonfilename = store_packet(rootdir, filename, json.dumps(allpackets))
    if b_redis:
        # If redis option, store data into redis
        potiron_redis.process_storage(jsonfilename, red)
    
    
if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Start the tool tshark and transform the output in a json document")
    parser.add_argument("-i", "--read", type=str, nargs=1, help="Compressed pcap file or pcap filename")
    parser.add_argument("-c", "--console", action='store_true', help="Log output also to console")
    parser.add_argument("-ff", "--fieldfilter", nargs='+',help="Parameters to filter fields to display")
    parser.add_argument("-o", "--directory", nargs=1, help="Output directory where the json documents are stored")
    parser.add_argument("-bf", "--bpffilter", type=str, nargs='+', help="BPF Filter")
    parser.add_argument("-r", "--redis", action='store_true', help="Store data directly in redis")
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    args = parser.parse_args()
    potiron.logconsole = args.console
    if args.read is not None:
        if os.path.exists(args.read[0]) is False:
            sys.stderr.write("The filename {} was not found\n".format(args.read[0]))
            sys.exit(1)
        inputfile = args.read[0]
    if args.fieldfilter is None:
        fieldfilter = []
    else:
        fieldfilter = args.fieldfilter
    if ('tcp.srcport' in fieldfilter or 'tcp.dstport' in fieldfilter or 'udp.srcport'  in fieldfilter or 'udp.dstport' in fieldfilter) and 'ip.proto' not in fieldfilter :
        sys.stderr.write('The protocol informations are required if you want to display a source or destination port\n')
        sys.exit(1)

    if args.directory is not None and os.path.isdir(args.directory[0]) is False:
        if not os.path.exists(args.directory[0]):
            create_dirs(args.directory[0], inputfile)
        else:
            sys.stderr.write("The root directory is not a directory\n")
            sys.exit(1)
        
    if args.bpffilter is not None:
        if len(args.bpffilter) == 1:
            bpffilter = args.bpffilter[0]
        else:
            bpffilter = ""
            for f in args.bpffilter:
                bpffilter += "{} ".format(f)
        bpf_filter += " && {}".format(bpffilter)

    b_redis = args.redis
    if b_redis:
        if args.unix is None:
            sys.stderr.write('A Unix socket must be specified.\n')
            sys.exit(1)
        usocket = args.unix[0]
        red = redis.Redis(unix_socket_path=usocket)

    if args.read is None:
        sys.stderr.write("At least a pcap file must be specified\n")
        sys.exit(1)
    try:
        rootdir = None
        if args.directory is not None:
            rootdir = args.directory[0]
        process_file(rootdir, inputfile, fieldfilter, b_redis)
    except OSError as e:
        sys.stderr.write("A processing error happend.{}.\n".format(e))
        sys.exit(1)
