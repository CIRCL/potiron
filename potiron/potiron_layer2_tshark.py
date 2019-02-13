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
from concurrent.futures import ProcessPoolExecutor
from potiron.potiron_isn_tshark import _create_json_packet
from potiron.potiron_tshark import day_from_filename, _set_json_timestamp
import json
import os
import potiron.potiron as potiron
import subprocess

_to_process = {'False': '_process_file', 'True': '_process_file_and_save_json'}


def layer2_process(red, files, logconsole):
    potiron.logconsole = logconsole
    for key, value in red.hgetall('PARAMETERS').items():
        globals()[f"_{key.upper()}"] = value
    if _ENABLE_JSON:
        globals()["_FIRST_PACKET"] = {feature[1:].lower(): globals()[feature] for feature in ("_FORMAT", "_TSHARK_FILTER")}
    globals()["_RED"] = red
    with ProcessPoolExecutor() as executor:
        for to_return in executor.map(globals()[_to_process[_ENABLE_JSON]], files):
            potiron.infomsg(to_return)


def _process_file(inputfile):
    to_set = {}
    to_incr, filename, sensorname = _get_data_structures(inputfile)
    if _RED.sismember("FILES", filename):
        return f'Filename {inputfile} was already imported ... skip ...\n'
    proc = subprocess.Popen(_CMD.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    lastday = day_from_filename(filename)
    _RED.sadd(f"{sensorname}_DAYS", lastday)
    count_key = f"{sensorname}_{lastday}_count"
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        timestamp = _set_json_timestamp(packet.pop('timestamp'))
        day, time = timestamp.split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            _RED.sadd(f"{sensorname}_DAYS", day)
            count_key = f"{sensorname}_{day}_count"
            lastday = day
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
    p = _RED.pipeline()
    for key, values in to_set.items():
        p.hmset(key, values)
    for key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(key, amount, value)
    p.execute()
    proc.wait()
    _RED.sadd("FILES", filename)
    return f"Layer2 data from {filename} parsed."


def _process_file_and_save_json(inputfile):
    to_set = {}
    to_incr, filename, sensorname = _get_data_structures(inputfile)
    if _RED.sismember("FILES", filename):
        return f'Filename {inputfile} was already imported ... skip ...\n'
    proc = subprocess.Popen(_CMD.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    first_packet = {"type": potiron.TYPE_SOURCE, "sensorname": sensorname, "filename": filename}
    first_packet.update(_FIRST_PACKET)
    allpackets = [first_packet]

    lastday = day_from_filename(filename)
    _RED.sadd(f"{sensorname}_DAYS", lastday)
    count_key = f"{sensorname}_{lastday}_count"
    packet_id = 0
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        packet['timestamp'] = _set_json_timestamp(packet['timestamp'])
        allpackets.append(_create_json_packet(packet, packet_id))
        day, time = packet.pop('timestamp').split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            _RED.sadd(f"{sensorname}_DAYS", day)
            count_key = f"{sensorname}_{day}_count"
            lastdady = day
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

    p = _RED.pipeline()
    for key, values in to_set.items():
        p.hmset(key, values)
    for key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(key, amount, value)
    p.execute()
    proc.wait()
    potiron.store_packet(_ROOTDIR, filename, json.dumps(allpackets))
    _RED.sadd("FILES", filename)
    return f"Layer2 data from {filename} parsed and stored in json format."


def _create_packet(line):
    line = line.decode().strip('\n')
    return {key: value for key, value in zip(potiron.layer2_json_fields, line.split(' '))}


def _get_data_structures(inputfile):
    to_incr = defaultdict(lambda: defaultdict(int))
    filename = os.path.basename(inputfile)
    sensorname = potiron.derive_sensor_name(inputfile)
    return to_incr, filename, sensorname
