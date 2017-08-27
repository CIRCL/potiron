#!/usr/bin/env python3
# -*- coding: utf-8 -*-


import argparse
import json
import redis
import sys
import os
import potiron

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Import data from json documents into redis.')
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
    sensorname = potiron.get_sensor_name(doc)
    revcreated = False
    lastday = None
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
            stime = di['timestamp']
            opcode = di['opcode']
            (day, time) = stime.split(' ')
            timestamp = "{}_{}".format(day,time)
            day = day.replace('-', '')
            if day != lastday:
                red.sadd("DAYS", day)
            # Store data into redis
            p = red.pipeline()
            countKeyname = '{}_{}_count'.format(sensorname,day)
            if opcode == '1':
                keyname = '{}_{}_{}'.format(sensorname, di['ipdst'], timestamp)
                p.hset(keyname, 'req_src_mac', di['ethsrc'])
                p.hset(keyname, 'req_src_ip', di['ipsrc'])
                p.hset(keyname, 'req_src_arp_mac', di['arpsrc'])
                p.zincrby(countKeyname, 'request', 1)
                timestampKey = timestamp
            else:
                keyname = '{}_{}_{}'.format(sensorname, di['ipsrc'], timestampKey)
                p.hset(keyname, 'rep_timestamp', stime)
                p.hset(keyname, 'rep_dst_ip', di['ipdst'])
                p.hset(keyname, 'rep_src_mac', di['ethsrc'])
                p.hset(keyname, 'rep_dst_mac', di['ethdst'])
                p.hset(keyname, 'rep_src_arp_mac', di['arpsrc'])
                p.hset(keyname, 'rep_dst_arp_mac', di['arpdst'])
                p.zincrby(countKeyname, 'reply', 1)
            p.execute()
    potiron.infomsg('Data from {} stored into redis'.format(filename))
                