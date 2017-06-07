#!/usr/bin/env python3


import subprocess
import os
import json
import sys
import potiron
import argparse
from potiron import infomsg, check_program
import datetime
        

bpf_filter = potiron.tshark_filter


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


def process_file(rootdir, filename, fieldfilter):
    if not check_program("tshark"):
        raise OSError("The program tshark is not installed")
    # FIXME Put in config file
    if rootdir is not None:
        create_dirs(rootdir, filename)
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
    for line in proc.stdout.readlines():
        packet_id = packet_id + 1
        line = line[:-1].decode()
        packet = {}
        tab_line = line.split(' ')
        for i in range(len(tab_line)):
            if fieldfilter:
                val = json_fields[tshark_fields.index(fieldfilter[i])]
            else:
                val = json_fields[i]
            packet[val] = tab_line[i]
        a, b = packet['timestamp'].split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
        stime = stime + "." + b[:-3]
        packet['timestamp'] = stime
        if 'length' in packet:
            ilength = -1
            try:
                ilength = int(packet['length'])
            except ValueError:
                pass
            packet['length'] = ilength
        if 'protocol' in packet:
            try:
                protocol = int(packet['protocol'])
                packet['protocol'] = protocol
            except ValueError:
                pass
            isport = -1
            sport = -1
            if 'tsport' in packet:
                if packet['protocol'] == 6:
                    sport = packet['tsport'] 
            if 'usport' in packet:
                if packet['protocol'] != 6:
                    sport = packet['usport']
            if ('tsport' in packet) or ('usport' in packet):
                try:
                    isport = int(sport)
                except ValueError:
                    pass
                packet['sport'] = isport
            idport = -1
            dport = -1
            if 'tdport' in packet:
                if packet['protocol'] == 6:
                    dport = packet['tdport']
            if 'udport' in packet:
                if packet['protocol'] != 6:
                    dport = packet['udport']
            if ('tdport' in packet) or ('udport' in packet):
                try:
                    idport = int(dport)
                except ValueError:
                    pass
                packet['dport'] = idport
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
        if 'ipttl' in packet:
            iipttl = -1
            try:
                iipttl = int(packet['ipttl'])
            except ValueError:
                pass
            packet['ipttl'] = iipttl
        if 'iptos' in packet:
            iiptos = -1
            try:
                iiptos = int(packet['iptos'], 0)
            except ValueError:
                pass
            packet['iptos'] = iiptos
        if 'tcpseq' in packet:
            itcpseq = -1
            try:
                itcpseq = int(packet['tcpseq'])
            except ValueError:
                pass
            packet['tcpseq'] = itcpseq
        if 'tcpack' in packet:
            itcpack = -1
            try:
                itcpack = int(packet['tcpack'])
            except ValueError:
                pass
            packet['tcpack'] = itcpack
        if 'icmpcode' in packet:
            iicmpcode = 255
            try:
                iicmpcode = int(packet['icmpcode'])
            except ValueError:
                pass
            packet['icmpcode'] = iicmpcode
        if 'icmptype' in packet:
            iicmptype = 255
            try:
                iicmptype = int(packet['icmptype'])
            except ValueError:
                pass
            packet['icmptype'] = iicmptype
        packet['packet_id'] = packet_id
        packet['type'] = potiron.TYPE_PACKET
        packet['state'] = potiron.STATE_NOT_ANNOATE
        # FIXME might consume a lot of memory
        allpackets.append(packet)

    # FIXME Implement polling because wait can last forever
    proc.wait()

    if proc.returncode != 0:
        errmsg = b"".join(proc.stderr.readlines())
        raise OSError("tshark failed. Return code {}. {}".format(proc.returncode, errmsg))
    store_packet(rootdir, filename, json.dumps(allpackets))
    
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Start the tool tshark and transform the output in a json document")
    parser.add_argument("-i", "--read", type=str, nargs=1, help="Compressed pcap file or pcap filename")
    parser.add_argument("-c", "--console", action='store_true', help="Log output also to console")
    parser.add_argument("-ff", "--fieldfilter", nargs='+',help="Parameters to filter fields to display")
    parser.add_argument("-o", "--directory", nargs=1, help="Output directory where the json documents are stored")
    parser.add_argument("-bf", "--bpffilter", type=str, nargs='+', help="BPF Filter")

    args = parser.parse_args()
    potiron.logconsole = args.console
    if args.read is not None:
        if os.path.exists(args.read[0]) is False:
            sys.stderr.write("The filename {} was not found\n".format(args.read[0]))
            sys.exit(1)
    
    if args.fieldfilter is None:
        fieldfilter = []
    else:
        fieldfilter = args.fieldfilter
    if ('tcp.srcport' in fieldfilter or 'tcp.dstport' in fieldfilter or 'udp.srcport'  in fieldfilter or 'udp.dstport' in fieldfilter) and 'ip.proto' not in fieldfilter :
        sys.stderr.write('The protocol informations are required if you want to display a source or destination port\n')
        sys.exit(1)

    if args.directory is not None and os.path.isdir(args.directory[0]) is False:
        sys.stderr.write("The root directory is not a directory\n")
        sys.exit(1)
        
    if args.bpffilter is not None:
        if len(args.bpffilter) == 1:
            bpffilter = args.bpffilter[0]
            bpf_filter += " && {}".format(bpffilter)
        else:
            sys.stderr.write("Due to the possibility your filter contains '|' caracter, it should be defined between simple or double quotes.\n")
            sys.exit(1)

    if args.read is None:
        sys.stderr.write("At least a pcap file must be specified\n")
        sys.exit(1)
    try:
        rootdir = None
        if args.directory is not None:
            rootdir = args.directory[0]
        process_file(rootdir, args.read[0], fieldfilter)
    except OSError as e:
        sys.stderr.write("A processing error happend.{}.\n".format(e))
        sys.exit(1)
