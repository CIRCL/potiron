#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2019 Christian Studer
#    Copyright (C) 2019 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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

from collections import defaultdict
from potiron.potiron_isn_tshark import _create_json_packet
from potiron.potiron_tshark import _set_json_timestamp
import concurrent.futures
import json
import os
import potiron.potiron as potiron
import subprocess

_to_process = {'False': '_process_file', 'True': '_process_file_and_save_json'}


def layer2_process(red, files):
    for key, value in red.hgetall('PARAMETERS').items():
        setattr(potiron, key.decode(), value.decode())
    potiron.redis_instance = red
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for to_return in executor.map(globals()[_to_process[potiron.enable_json]], files):
            potiron.infomsg(to_return)


def _process_file(inputfile):
    to_set = {}
    red, to_incr, filename, sensorname = _get_data_structures(inputfile)
    if red.sismember("FILES", filename):
        return f'[INFO] Filename {inputfile} was already imported ... skip ...\n'
    proc = subprocess.Popen(potiron.cmd.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    lastday = None
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        timestamp = _set_json_timestamp(packet.pop('timestamp'))
        day, time = timestamp.split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            red.sadd("DAYS", day)
        count_key = f"{sensorname}_{day}_count"
        if packet['opcode'] == '1':
            keyname = f"{sensorname}_{packet['ipdst']}_{timestamp}"
            values = [packet[value] for value in ('ethsrc', 'ipsrc', 'arpsrc')]
            to_set[keyname] = {key: value for key, value in zip(('req_src_mac', 'req_src_ip', 'req_src_arp_mac'), values)}
            to_incr[count_key]['request'] += 1
            timestamp_key = timestamp
        else:
            keyname = f"{sensorname}_{packet['ipsrc']}_{timestamp_key}"
            values = [packet[value] for value in ('ipdst', 'ethsrc', 'ethdst', 'arpsrc', 'arpdst')]
            keys = ('rep_dst_ip', 'rep_src_mac', 'rep_dst_mac', 'rep_src_arp_mac', 'rep_dst_arp_mac')
            to_set[keyname] = {key: value for key, value in zip(keys, values)}
            to_set[keyname]['rep_timestamp'] = timestamp
            to_incr[count_key]['reply'] += 1
    p = red.pipeline()
    for key, values in to_set.items():
        p.hmset(key, values)
    for key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(key, amount, value)
    p.execute()
    proc.wait()
    red.sadd("FILES", filename)
    return f"Layer2 data from {filename} parsed."


def _process_file_and_save_json(inputfile):
    to_set = {}
    red, to_incr, filename, sensorname = _get_data_structures(inputfile)
    if red.sismember("FILES", filename):
        return f'[INFO] Filename {inputfile} was already imported ... skip ...\n'
    proc = subprocess.Popen(potiron.cmd.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    allpackets = [{"type": potiron.TYPE_SOURCE, "sensorname": sensorname,
                   "filename": os.path.basename(inputfile), "bpf": potiron.tshark_filter}]

    lastday = None
    packet_id = 0
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        packet['timestamp'] = _set_json_timestamp(packet['timestamp'])
        allpackets.append(_create_json_packet(packet, packet_id))
        day, time = packet.pop('timestamp').split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            red.sadd("DAYS", day)
        count_key = f"{sensorname}_{day}_count"
        if packet['opcode'] == '1':
            keyname = f"{sensorname}_{packet['ipdst']}_{timestamp}"
            values = [packet[value] for value in ('ethsrc', 'ipsrc', 'arpsrc')]
            to_set[keyname] = {key: value for key, value in zip(('req_src_mac', 'req_src_ip', 'req_src_arp_mac'), values)}
            to_incr[count_key]['request'] += 1
            timestamp_key = timestamp
        else:
            keyname = f"{sensorname}_{packet['ipsrc']}_{timestamp_key}"
            values = [packet[value] for value in ('ipdst', 'ethsrc', 'ethdst', 'arpsrc', 'arpdst')]
            keys = ('rep_dst_ip', 'rep_src_mac', 'rep_dst_mac', 'rep_src_arp_mac', 'rep_dst_arp_mac')
            to_set[keyname] = {key: value for key, value in zip(keys, values)}
            to_set[keyname]['rep_timestamp'] = timestamp
            to_incr[count_key]['reply'] += 1
        packet_id += 1

    p = red.pipeline()
    for key, values in to_set.items():
        p.hmset(key, values)
    for key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(key, amount, value)
    p.execute()
    proc.wait()
    potiron.store_packet(potiron.rootdir, filename, json.dumps(allpackets))
    red.sadd("FILES", filename)
    return f"Layer2 data from {filename} parsed and stored in json format."


def _create_packet(line):
    line = line.decode().strip('\n')
    return {key: value for key, value in zip(potiron.layer2_json_fields, line.split(' '))}


def _get_data_structures(inputfile):
    red = potiron.redis_instance
    to_incr = defaultdict(lambda: defaultdict(int))
    filename = os.path.basename(inputfile)
    sensorname = potiron.derive_sensor_name(inputfile)
    return red, to_incr, filename, sensorname
