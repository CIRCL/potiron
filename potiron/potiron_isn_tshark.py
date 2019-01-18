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
from potiron.potiron_tshark import _set_redis_timestamp, _set_json_timestamp
import concurrent.futures
import os
import json
import potiron.potiron as potiron
import subprocess

non_index = ['', 'timestamp', 'state', 'type', 'sport', 'dport']
_to_process = {'False': '_process_file', 'True': '_process_file_and_save_json'}


def isn_process(red, files):
    for key, value in red.hgetall('PARAMETERS').items():
        setattr(potiron, key.decode(), value.decode())
    potiron.redis_instance = red
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for to_return in executor.map(globals()[_to_process[potiron.enable_json]], files):
            potiron.infomsg(to_return)


def _process_file(inputfile):
    red, to_set, filename, sensorname = _get_data_structures(inputfile)
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
        ports = "_".join([f"{port}{packet.pop(value)}" for port, value in zip(('src', 'dst'), ('sport', 'dport'))])
        key = f"{sensorname}_{ports}_{timestamp}"
        to_set[key] = {isn_type: value for isn_type, value in packet.items()}

    p = red.pipeline()
    for key, item in to_set.items():
        p.hmset(key, item)
    p.execute()
    red.sadd("FILES", filename)
    proc.wait()
    return f'ISN Data from {filename} parsed.'


def _process_file_and_save_json(inputfile):
    red, to_set, filename, sensorname = _get_data_structures(inputfile)
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
        timestamp = f'{day}_{time}'
        day = day.replace('-', '')
        if day != lastday:
            red.sadd("DAYS", day)
        ports = "_".join([f"{port}{packet.pop(value)}" for port, value in zip(('src', 'dst'), ('sport', 'dport'))])
        key = f"{sensorname}_{ports}_{timestamp}"
        to_set[key] = {isn_type: value for isn_type, value in packet.items()}

    p = red.pipeline()
    for key, item in to_set.items():
        p.hmset(key, item)
    p.execute()
    potiron.store_packet(potiron.rootdir, filename, json.dumps(allpackets))
    red.sadd("FILES", filename)
    proc.wait()
    return f'ISN Data from {filename} parsed and stored in json format.'


def _create_packet(line):
    line = line.decode().strip('\n')
    return {key: value for key, value in zip(potiron.isn_json_fields, line.split(' '))}


def _create_json_packet(packet, packet_id):
    to_return = {'packet_id': packet_id, 'type': potiron.TYPE_PACKET, 'state': potiron.STATE_NOT_ANNOTATE}
    to_return.update(packet)
    return to_return


def _define_redis_key(lastday, packet, red, sensorname, timestamp):
    day, time = timestamp.split(' ')
    timestamp = f"{day}_{time}"
    day = day.replace('-', '')
    if day != lastday:
        red.sadd("DAYS", day)
    ports = "_".join([f"{port}{packet.pop(value)}" for port, value in zip(('src', 'dst'), ('sport', 'dport'))])
    return f"{sensorname}_{ports}_{timestamp}"


def _get_data_structures(inputfile):
    red = potiron.redis_instance
    to_set = defaultdict(dict)
    filename = os.path.basename(inputfile)
    sensorname = potiron.derive_sensor_name(inputfile)
    return red, to_set, filename, sensorname
