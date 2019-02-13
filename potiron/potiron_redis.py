#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2014 Gerard Wagener
#    Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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
from lib.helpers import get_homedir
from potiron.potiron_tshark import day_from_filename
import json
import potiron.potiron as potiron
import sys

_ck_mapping = {"False": "_get_redis_key", "True": "_get_redis_key_with_ck"}
_storage_mapping = {format: f"_store_{format}_data" for format in ('standard', 'isn', 'layer2')}
_isn_fields = ('tcpseq', 'tcpack')


def process_storage(red, files, ck, logconsole):
    potiron.logconsole = logconsole
    for key, value in red.hgetall('PARAMETERS').items():
        globals()[f"_{key.upper()}"] = value
    globals()['_RED'] = red
    if _FORMAT == 'standard':
        _check_ck(red, ck)
        globals()['_JSON_FIELDS'] = red.lrange("JSON_FIELDS", 0, -1)
        if ck == 'True':
            globals()['_PROTOCOLS'] = potiron.define_protocols(get_homedir() / "doc/protocols")
        globals()['_KEY_FUNCTION'] = globals()[_ck_mapping[str(ck)]]
    with ProcessPoolExecutor() as executor:
        for to_return in executor.map(_store_file, files):
            potiron.infomsg(to_return)


def _store_file(inputfile):
    with open(inputfile, 'rt', encoding='utf-8') as f:
        allpackets = json.loads(f.read())
    status = _check_parameters(allpackets.pop(0))
    if isinstance(status, str):
        return status
    sensorname, filename = status
    if _RED.sismember("FILES", filename):
        return f'Filename {filename} was already imported ... skip ...\n'
    return globals()[_storage_mapping[_FORMAT]](allpackets, sensorname, filename)


def _store_isn_data(allpackets, sensorname, filename):
    to_set = {}
    lastday = day_from_filename(filename)
    _RED.sadd("DAYS", lastday)
    for packet in allpackets:
        day, time = packet.pop('timestamp').split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            _RED.sadd("DAYS", day)
            lastday = day
        ports = "_".join([f"{port}{packet.pop(value)}" for port, value in zip(('src', 'dst'), ('sport', 'dport'))])
        key = f"{sensorname}_{ports}_{timestamp}"
        to_set[key] = {isn_type: packet[isn_type] for isn_type in _isn_fields}
    p = _RED.pipeline()
    for key, item in to_set.items():
        p.hmset(key, item)
    p.execute()
    _RED.sadd("FILES", filename)
    return f"ISN data from {filename} parsed from JSON file."


def _store_layer2_data(allpackets, sensorname, filename):
    to_set = {}
    to_incr = defaultdict(lambda: defaultdict(int))
    lastday = day_from_filename(filename)
    _RED.sadd("DAYS", lastday)
    count_key = f"{sensorname}_{lastday}_count"
    for packet in allpackets:
        day, time = packet.pop('timestamp').split(' ')
        timestamp = f"{day}_{time}"
        day = day.replace('-', '')
        if day != lastday:
            _RED.sadd("DAYS", day)
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
    _RED.sadd("FILES", filename)
    return f"Layer2 data from {filename} parsed from JSON file."


def _store_standard_data(allpackets, sensorname, filename):
    to_incr = defaultdict(lambda: defaultdict(int))
    lastday = day_from_filename(filename)
    _RED.sadd("DAYS", lastday)
    for packet in allpackets:
        redis_key, day = _KEY_FUNCTION(packet, sensorname)
        if day != lastday:
            _RED.sadd("DAYS", day)
            lastday = day
        for field in _JSON_FIELDS:
            to_incr[f"{redis_key}:{field}"][packet[field]] += 1
    p = _RED.pipeline()
    for key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(key, amount, value)
    p.execute()
    _RED.sadd("FILES", filename)
    return f"Data from {filename} parsed from JSON file."


def _check_ck(red, ck):
    redis_ck = red.hget("PARAMETERS", 'ck')
    if redis_ck != str(ck):
        sys.exit(f"[INFO] CK parameter to use combined keys is set to {ck}, but in the redis instance you want to store data from you JSON files, this value is set to {redis_ck}. \
        Please either {'do not use' if ck else 'use'} '-ck' parameter in your command, or use a different redis instance where it is {'not set' if ck else 'set'}.")


def _check_parameters(packet):
    format = packet.pop('format')
    if format != _FORMAT:
        return f'Format error: You want to store data in {format} format but this redis instance is used to store data in {_FORMAT} format.'
    if format == 'standard':
        if sorted(packet['json_fields']) != sorted(_JSON_FIELDS):
            return f'Fields you are trying to ingest are not the same as the ones currently used: {_JSON_FIELDS}'
    if packet['tshark_filter'] != _TSHARK_FILTER:
        return f"Error with the tshark_filter parameter value: {packet['thsark_filter']}, which should be {_TSHARK_FILTER} as mentioned in the redis parameters."
    return [packet[feature] for feature in ('sensorname', 'filename')]


def _get_redis_key(packet, sensorname):
    day = packet.pop('timestamp').split(' ')[0].replace('-', '')
    return f"{sensorname}:{day}", day


def _get_redis_key_with_ck(pacekt, sensorname):
    day = packet.pop('timestamp').split(' ')[0].replace('-', '')
    return f"{sensorname}:{_PROTOCOLS[packet['protocol']]}:{day}", day
