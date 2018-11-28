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

import subprocess, os, json, sys, potiron, argparse, redis, datetime, potiron_redis

class TsharkPacketsParser():
    def __init__(self, **kwargs):
        print(kwargs)
        for arg_key, arg_value in kwargs.items():
            setattr(self, arg_key, arg_value)
        self.bpf = potiron.tshark_filter
        self.tshark_fields = potiron.tshark_fields
        self.json_fields = potiron.json_fields
        self.special_fields = {'length': -1, 'ipttl': -1, 'iptos': 0, 'tcpseq': -1,
                               'tcpack': -1, 'icmpcode': 255, 'icmptype': 255}

    # Complete the packet with values that need some verifications
    def fill_packet(self, packet):
        # Convert timestamp
        a, b = packet['timestamp'].split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        if self.disable_json:
            stime = dobj.strftime("%Y%m%d")
        else:
            stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
            stime = stime + "." + b[:-3]
        packet['timestamp'] = stime
        try:
            protocol = int(packet['protocol'])
            packet['protocol'] = protocol
        except ValueError:
            pass
        sport = -1
        dport = -1
        if 'tsport' in packet and packet['tsport']:
            sport = packet['tsport']
        elif 'usport' in packet and packet['usport']:
            sport = packet['usport']
        if 'tdport' in packet and packet['tdport']:
            dport = packet['tdport']
        elif 'udport' in packet and packet['udport']:
            dport = packet['udport']
        if sport != -1:
            packet['sport'] = sport
        if dport != -1:
            packet['dport'] = dport
        for port in ('tsport', 'usport', 'tdport', 'udport'):
            if port in packet: del packet[port]
        if 'ipsrc' in packet and packet['ipsrc'] == '-':
            packet['ipsrc'] = None
        if 'ipdst' in packet and packet['ipdst'] == '-':
            packet['ipdst'] = None

    def create_packet(self, line):
        line = line[:-1].decode()
        packet = {}
        tab_line = line.split(' ')
        for i in range(len(tab_line)):
            if self.fieldfilter:
                valname = self.json_fields[tshark_fields.index(self.fieldfilter[i])]
            else:
                valname = self.json_fields[i]
            if valname in self.special_fields:
                v = self.special_fields[valname]
                try:
                    v = int(tab_line[i])
                except ValueError:
                    pass
                packet[valname] = v
            else:
                packet[valname] = tab_line[i]
        return packet

    # Process data saving into json file and storage into redis
    def process_file(self):
        if self.disable_json:
            fn = os.path.basename(self.inputfile)
            if self.red.sismember("FILES", fn):
                sys.stderr.write('[INFO] Filename ' + fn + ' was already imported ... skip ...\n')
                sys.exit(0)
            # FIXME Users have to be carefull with the files extensions to not process data from capture files
            # FIXME (potiron-json-tshark module), and the same sample again from json files (potiron_redis module)

            # List of fields that are included in the json documents that should not be ranked
            # FIXME Put this as argument to the program as this list depends on the documents that is introduced
            non_index = ['', 'filename', 'sensorname', 'timestamp', 'packet_id']

        # If tshark is not installed, exit and raise the error
        if not potiron.check_program("tshark"):
            raise OSError("The program tshark is not installed")
        # FIXME Put in config file

        cmd = "tshark -n -q -Tfields "
        if self.fieldfilter:
            if 'frame.time_epoch' not in self.fieldfilter:
                self.fieldfilter.insert(0, 'frame.time_epoch')
            if 'ip.proto' not in self.fieldfilter:
                self.fieldfilter.insert(1, 'ip.proto')
            for p in self.fieldfilter:
                cmd += "-e {} ".format(p)
        else:
            for f in self.tshark_fields:
                cmd += "-e {} ".format(f)
        cmd += "-E header=n -E separator=/s -E occurrence=f -Y '{}' -r {} -o tcp.relative_sequence_numbers:FALSE".format(self.bpf, self.inputfile)
        print(cmd)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

        # Name of the honeypot
        sensorname = potiron.derive_sensor_name(self.inputfile)

        if self.disable_json:
            # If redis key 'BPF' already exists
            if self.red.keys('BPF'):
                # Check is the current bpf is the same as the one previously used
                if not self.red.sismember('BPF', self.bpf):
                    bpf_string = str(self.red.smembers('BPF'))
                    sys.stderr.write('[INFO] BPF for the current data is not the same as the one used in the data already stored here : {}\n'.format(bpf_string[3:-2]))
                    sys.exit(0)
            # On the other case, add the bpf in the key 'BPF'
            else:
                red.sadd('BPF', self.bpf)

            # If combined keys are used
            if self.ck:
                # If redis key 'CK' already exists ...
                if self.red.keys('CK'):
                    # ... BUT is set to 'Ńone', then combined keys are not used in the data already stored in redis
                    if self.red.sismember('CK','NO'):
                        sys.stderr.write('[INFO] Combined key are not used in this redis dataset.\n')
                        sys.exit(0)
                # If redis key 'CK' does not exist ...
                else:
                    self.red.sadd('CK','YES')
            # If combined key are not used, the key 'CK' should exist anyway, with the value 'None'
            else:
                # If redis key 'CK' already exists ...
                if self.red.keys('CK'):
                    # ... BUT is not set to 'None', then combined keys are used in the data already stored in redis
                    if self.red.sismember('CK','YES'):
                        sys.stderr.write('[INFO] Combined key are used in this redis dataset.\n')
                        sys.exit(0)
                # On the other case, we add it
                else:
                    self.red.sadd('CK','NO')

            self.red.sadd("FILES", fn)
            potiron_path = os.environ.get("POTIRON_HOME")
            protocols_path = "{}doc/protocols".format(potiron_path)
            protocols = potiron.define_protocols(protocols_path)

            lastday = None
            prot = []
            for line in proc.stdout.readlines():
                packet = self.create_packet(line)
                self.fill_packet(packet)
                timestamp = packet['timestamp']
                if self.ck:
                    protocol = protocols[str(packet['protocol'])]
                    rKey = "{}:{}:{}".format(sensorname, protocol, timestamp)
                    if protocol not in prot:
                        prot.append(protocol)
                else:
                    rKey = "{}:{}".format(sensorname, timestamp)
                p = self.red.pipeline()
                if timestamp != lastday:
                    p.sadd("DAYS", timestamp)
                    lastday = timestamp
                for f in packet:
                    if f not in non_index:
                        feature = packet[f]
                        redisKey = "{}:{}".format(rKey, f)
                        p.sadd("FIELDS", f)
                        p.zincrby(redisKey, 1, feature)
                p.execute()
            if self.ck:
                for pr in prot:
                    self.red.sadd("PROTOCOLS", pr)
            potiron.infomsg('Data from {} stored into redis'.format(self.inputfile))

        else:
            allpackets = []
            # Describe the source
            allpackets.append({"type": potiron.TYPE_SOURCE, "sensorname": sensorname,
                               "filename": os.path.basename(self.inputfile), "bpf": self.bpf})
            # Each packet has a incremental numeric id
            # A packet is identified with its sensorname filename and packet id for
            # further aggregation with meta data.
            # Assumption: Each program process the pcap file the same way?
            packet_id = 0

            for line in proc.stdout.readlines():
                packet_id = packet_id + 1
                packet = self.create_packet(line)
                fill_packet(packet, self.disable_json)
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
            jsonfilename = potiron.store_packet(self.rootdir, self.inputfile, json.dumps(allpackets))
            if self.b_redis:
                # If redis option, store data into redis
                potiron_redis.process_storage(jsonfilename, self.red, self.ck)


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Start the tool tshark and transform the output in a json document")
    parser.add_argument("-i", "--input", type=str, nargs=1, help="Pcap or compressed pcap filename")
    parser.add_argument("-c", "--console", action='store_true', help="Log output also to console")
    parser.add_argument("-ff", "--fieldfilter", nargs='+',help='Parameters to filter fields to display (ex: "tcp.srcport udp.srcport")')
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Output directory where the json documents will be stored")
    parser.add_argument("-tf", "--tsharkfilter", type=str, nargs='+', help='Tshark Filter (with wireshark/tshark synthax. ex: "ip.proto == 6")')
    parser.add_argument("-r", "--redis", action='store_true', help="Store data directly in redis")
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-ck', '--combined_keys', action='store_true', help='Set if combined keys should be used')
    parser.add_argument('-dj', '--disable_json', action='store_true', help='Disable storage into json files and directly store data in Redis')
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
    if args.fieldfilter is None:
        fieldfilter = []
    else:
        fieldfilter = args.fieldfilter

    if args.tsharkfilter is not None:
        if len(args.tsharkfilter) == 1:
            tsharkfilter = args.tsharkfilter[0]
            bpf += " && {}".format(tsharkfilter)
        else:
            tsharkfilter = ""
            for f in args.tsharkfilter:
                tsharkfilter += "{} ".format(f)
            bpf += " && {}".format(tsharkfilter[:-1])

    b_redis = args.redis
    disable_json = args.disable_json

    if disable_json:
        b_redis = True
        rootdir = None
    else:
        if args.outputdir is None:
            sys.stderr.write("You should specify an output directory.\n")
            sys.exit(1)
        else:
            rootdir = args.outputdir[0]
            potiron.create_dirs(rootdir, inputfile)
            if os.path.isdir(rootdir) is False:
                sys.stderr.write("The root directory is not a directory\n")
                sys.exit(1)
    if b_redis:
        if args.unix is None:
            sys.stderr.write('A Unix socket must be specified.\n')
            sys.exit(1)
        usocket = args.unix[0]
        red = redis.Redis(unix_socket_path=usocket)

    ck = args.combined_keys

    parser = TsharkPacketsParser(rootdir=rootdir, inputfile=inputfile, fieldfilter=fieldfilter,
                                 b_redis=b_redis, disable_json=disable_json, ck=ck, red=red)
    parser.process_file()
