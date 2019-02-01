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
from potiron.potiron_tshark import _set_redis_timestamp, _set_json_timestamp
import os
import json
import potiron.potiron as potiron
import subprocess

non_index = ['', 'timestamp', 'state', 'type', 'sport', 'dport']
_to_process = {'False': '_process_file', 'True': '_process_file_and_save_json'}


def isn_process(red, files, logconsole):
    potiron.logconsole = logconsole
    for key, value in red.hgetall('PARAMETERS').items():
        globals()[f"_{key.decode().upper()}"] = value.decode()
    if _ENABLE_JSON:
        globals()["_FIRST_PACKET"] = {feature[1:].lower(): globals()[feature] for feature in ("_FORMAT", "_TSHARK_FILTER")}
    globals()["_RED"] = red
    with ProcessPoolExecutor() as executor:
        for to_return in executor.map(globals()[_to_process[_ENABLE_JSON]], files):
            potiron.infomsg(to_return)


def _process_file(inputfile):
    to_set, filename, sensorname = _get_data_structures(inputfile)
    if _RED.sismember("FILES", filename):
        return f'Filename {inputfile} was already imported ... skip ...\n'
    proc = subprocess.Popen(_CMD.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    lastday = None
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        timestamp = _set_json_timestamp(packet.pop('timestamp'))
        day, time = timestamp.split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            _RED.sadd("DAYS", day)
        ports = "_".join([f"{port}{packet.pop(value)}" for port, value in zip(('src', 'dst'), ('sport', 'dport'))])
        key = f"{sensorname}_{ports}_{timestamp}"
        to_set[key] = {isn_type: value for isn_type, value in packet.items()}

    p = _RED.pipeline()
    for key, item in to_set.items():
        p.hmset(key, item)
    p.execute()
    proc.wait()
    _RED.sadd("FILES", filename)
    return f'ISN Data from {filename} parsed.'


def _process_file_and_save_json(inputfile):
    to_set, filename, sensorname = _get_data_structures(inputfile)
    if _RED.sismember("FILES", filename):
        return f'Filename {inputfile} was already imported ... skip ...\n'
    proc = subprocess.Popen(_CMD.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    first_packet = {"type": potiron.TYPE_SOURCE, "sensorname": sensorname, "filename": filename}
    first_packet.update(_FIRST_PACKET)
    allpackets = [first_packet]

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
            _RED.sadd("DAYS", day)
        ports = "_".join([f"{port}{packet.pop(value)}" for port, value in zip(('src', 'dst'), ('sport', 'dport'))])
        key = f"{sensorname}_{ports}_{timestamp}"
        to_set[key] = {isn_type: value for isn_type, value in packet.items()}
        packet_id += 1

    p = _RED.pipeline()
    for key, item in to_set.items():
        p.hmset(key, item)
    p.execute()
    proc.wait()
    potiron.store_packet(_ROOTDIR, filename, json.dumps(allpackets))
    _RED.sadd("FILES", filename)
    return f'ISN Data from {filename} parsed and stored in json format.'


def _create_packet(line):
    line = line.decode().strip('\n')
    return {key: value for key, value in zip(potiron.isn_json_fields, line.split(' '))}


def _create_json_packet(packet, packet_id):
    to_return = {'packet_id': packet_id, 'type': potiron.TYPE_PACKET, 'state': potiron.STATE_NOT_ANNOTATE}
    to_return.update(packet)
    return to_return


def _get_data_structures(inputfile):
    to_set = defaultdict(dict)
    filename = os.path.basename(inputfile)
    sensorname = potiron.derive_sensor_name(inputfile)
    return to_set, filename, sensorname
