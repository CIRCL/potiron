#!/usr/bin/env python3

import argparse
import json
import redis
import sys
import os
import potiron

non_index = ['', 'filename', 'sensorname', 'packet_id','timestamp', 'length', 'protocol', 'sport',
             'dport', 'ipsrc', 'ipdst', 'ipttl', 'iptos', 'icmpcode', 'icmptype', 'type', 'state']

parser = argparse.ArgumentParser(description='Import json documents into redis time series')
parser.add_argument('-i', '--input', type=str, nargs=1, help='Filename of a json document that should be imported.')
parser.add_argument('-u', '--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
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

if args.input is None:
    sys.stderr.write('A filename must be specified\n')
    sys.exit(1)
filename = args.input[0]

# Check if file was already imported
fn = os.path.basename(filename)
if red.sismember("FILES", fn):
    sys.stderr.write('[INFO] Filename ' + fn + ' was already imported ... skip ...\n')
    sys.exit(0)
red.sadd("FILES", fn)

f = open(filename, 'r')
doc = json.load(f)
f.close()

# Record local dictionaries
local_dicts = dict()
rev_dics = dict()

# Get sensorname assume one document per sensor name

item = doc[0]
bpf = item['bpf']
if red.keys('BPF'):
    if not red.sismember('BPF', bpf):
        red.srem('FILES', fn)
        bpf_string = str(red.smembers('BPF'))
        sys.stderr.write('[INFO] BPF for the current data is not the same as the one used in the data already stored here : {}\n'.format(bpf_string[3:-2]))
        sys.exit(0)
else:
    red.sadd('BPF', bpf)
# FIXME documents must include at least a sensorname and a timestamp
# FIXME check timestamp format
sensorname = potiron.get_sensor_name(doc)
lastday = None
revcreated = False

for di in doc:
    if di["type"] > potiron.DICT_LOWER_BOUNDARY:
        local_dicts[di["type"]] = di
    if di["type"] == potiron.TYPE_PACKET:
        if not revcreated:
            # FIXME if a json file was annotated twice the resulting json file
            # includes two dictionaries of the same type
            # Only the last one is considered
            rev_dics = potiron.create_reverse_local_dicts(local_dicts)
            revcreated = True
        timestamp = di['timestamp']
        sport = di['sport']
        dport = di['dport']
        (day, time) = timestamp.split(' ')
        timestamp = "{}_{}".format(day,time)
        day = day.replace('-', '')
        if day != lastday:
            red.sadd("DAYS", day)
        p = red.pipeline()
        for k in list(di.keys()):
            if k not in non_index:
                feature = di[k]
                if k.startswith(potiron.ANNOTATION_PREFIX):
                    feature = potiron.translate_dictionaries(rev_dics, red, k, di[k])
                    # Create the links between annotations and their objects
                    idn = potiron.get_dictionary_id(k)
                    obj = potiron.get_annotation_origin(di, k)
                    if obj is not None and idn is not None:
                        kn = "AR_{}_{}".format(idn, obj)
                        p.set(kn, feature)
                keyname = "{}_src{}_dst{}_{}".format(sensorname,sport,dport,timestamp)
                p.hset(keyname,k,feature)
        p.execute()