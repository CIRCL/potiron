#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2017-2019 Christian Studer
#    Copyright (C) 2017-2019 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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
from potiron.potiron_parameters import extract_json_fields
import datetime
import json
import os
import potiron.potiron as potiron
import subprocess
import sys


_port_mapping = {'1': '_check_udport', '2': '_check_tdport',
                '3': '_check_dst_ports', '4': '_check_usport',
                '5': '_check_udp_ports', '6': '_check_us_td_ports',
                '7': '_check_us_dst_ports', '8': '_check_tsport',
                '9': '_check_ts_ud_ports', '10': '_check_tcp_ports',
                '11': '_check_ts_dst_ports', '12': '_check_src_ports',
                '13': '_check_src_ud_ports', '14': '_check_src_td_ports',
                '15': '_check_all_ports'}
_ck_mapping = {'True': '_combined_redis_key', 'False': '_simple_redis_key'}
_dj_mapping = {'True': '_set_redis_timestamp', 'False': '_set_json_timestamp'}
_ip_mapping = {'1': ('ipdst'), '2': ('ipsrc'), '3': ('ipsrc', 'ipdst')}
_to_process = {'False': '_process_file', 'True': '_process_file_and_save_json'}

non_index = ['', 'filename', 'sensorname', 'timestamp', 'packet_id']
special_fields = {'length': -1, 'ipttl': -1, 'iptos': 0, 'tcpseq': -1,
                  'tcpack': -1, 'icmpcode': 255, 'icmptype': 255}


def standard_process(red, files):
    globals()["_FIELDS"] = [field.decode() for field in red.lrange('FIELDS', 0, -1)]
    globals()["_JSON_FIELDS"] = extract_json_fields(_FIELDS)
    for key, value in red.hgetall('PARAMETERS').items():
        globals()[f"_{key.decode().upper()}"] = value.decode()
    if _ENABLE_JSON:
        globals()["_FIRST_PACKET"] = {feature[1:].lower(): globals()[feature] for feature in ("_FORMAT", "_CK", "_TSHARK_FILTER", "_JSON_FIELDS")}
    if _CK:
        globals()["_PROTOCOLS"] = potiron.define_protocols(get_homedir() / "doc/protocols")
    globals()["_RED"] = red
    with ProcessPoolExecutor() as executor:
        for to_return in executor.map(globals()[_to_process[_ENABLE_JSON]], files):
            potiron.infomsg(to_return)


def _process_file(inputfile):
    to_add, to_incr, filename, sensorname = _get_data_structures(inputfile)
    if _RED.sismember("FILES", filename):
        return f'[INFO] Filename {inputfile} was already imported ... skip ...\n'
    # FIXME Users have to be carefull with the files extensions to not process data from capture files
    # FIXME (potiron-json-tshark module), and the same sample again from json files (potiron_redis module)

    # List of fields that are included in the json documents that should not be ranked
    # FIXME Put this as argument to the program as this list depends on the documents that is introduced
    proc = subprocess.Popen(_CMD.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    to_add["FILES"].add(filename)

    lastday = None
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        packet['timestamp'] = _set_redis_timestamp(packet['timestamp'])
        timestamp = packet['timestamp']
        rKey = globals()[_ck_mapping[_CK]](packet, sensorname, to_add)
        if timestamp != lastday:
            to_add["DAYS"].add(timestamp)
            lastday = timestamp
        for feature, value in packet.items():
            if feature not in non_index:
                redis_key = f"{rKey}:{feature}"
                to_incr[redis_key][value] += 1
    p = _RED.pipeline()
    for key, values in to_add.items():
        p.sadd(key, *list(values))
    for redis_key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(redis_key, amount, value)
    p.execute()
    proc.wait()
    return f'Data from {filename} parsed.'


def _process_file_and_save_json(inputfile):
    to_add, to_incr, filename, sensorname = _get_data_structures(inputfile)
    if _RED.sismember("FILES", filename):
        return f'[INFO] Filename {inputfile} was already imported ... skip ...\n'
    # FIXME Users have to be carefull with the files extensions to not process data from capture files
    # FIXME (potiron-json-tshark module), and the same sample again from json files (potiron_redis module)

    # List of fields that are included in the json documents that should not be ranked
    # FIXME Put this as argument to the program as this list depends on the documents that is introduced
    proc = subprocess.Popen(_CMD.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    to_add["FILES"].add(filename)
    first_packet = {"type": potiron.TYPE_SOURCE, "sensorname": sensorname, "filename": filename}
    first_packet.update(_FIRST_PACKET)
    allpackets = [first_packet]
    lastday = None
    packet_id = 0
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        timestamp = packet['timestamp']
        packet['timestamp'] = _set_redis_timestamp(packet['timestamp'])
        rKey = globals()[_ck_mapping[_CK]](packet, sensorname, to_add)
        if timestamp != lastday:
            to_add["DAYS"].add(timestamp)
            lastday = timestamp
        for feature, value in packet.items():
            if feature not in non_index:
                redis_key = f"{rKey}:{feature}"
                to_incr[redis_key][value] += 1
        packet['timestamp'] = _set_json_timestamp(timestamp)
        packet['packet_id'] = packet_id
        packet['type'] = potiron.TYPE_PACKET
        packet['state'] = potiron.STATE_NOT_ANNOTATE
        allpackets.append(packet)
        packet_id += 1
    p = _RED.pipeline()
    for key, values in to_add.items():
        p.sadd(key, *list(values))
    for redis_key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(redis_key, amount, value)
    p.execute()
    potiron.store_packet(_ROOTDIR, filename, json.dumps(allpackets))
    proc.wait()
    return f'Data from {filename} parsed and stored in json format.'


def _create_packet(line):
    line = line.decode().strip('\n')
    packet = {key: value for key, value in zip(_FIELDS, line.split(' '))}
    for special_field, value in special_fields.items():
        if special_field in packet and not packet[special_field]:
            packet[special_field] = value
    packet = globals()[_TO_CALL](packet)
    return packet


def _get_data_structures(inputfile):
    to_add = defaultdict(set)
    to_incr = defaultdict(lambda: defaultdict(int))
    filename = os.path.basename(inputfile)
    # Name of the honeypot
    sensorname = potiron.derive_sensor_name(inputfile)
    return to_add, to_incr, filename, sensorname


################################################################################
##             FUNCTIONS TO HANDLE SOME SPECIAL FIELDS IN PACKETS             ##
################################################################################


def _cannot_be_int(protocol):
    try:
        int(protocol)
        is_int = False
    except Exception:
        is_int = True
    return is_int


def _check_udport(packet):
    packet['dport'] = _handle_port(packet['udport'])
    del packet['udport']


def _check_tdport(packet):
    packet['dport'] = _handle_port(packet['tdport'])
    del packet['tdport']


def _check_dst_ports(packet):
    port = 'dport'
    tport = _get_port_from_packet(packet, f't{port}')
    uport = _get_port_from_packet(packet, f'u{port}')
    packet[port] = tport if tport != -1 else uport


def _check_usport(packet):
    packet['sport'] = _handle_port(packet['usport'])
    del packet['usport']


def _check_udp_ports(packet):
    _check_usport(packet)
    _check_udport(packet)


def _check_us_td_ports(packet):
    _check_usport(packet)
    _check_tdport(packet)


def _check_us_dst_ports(packet):
    _check_usport(packet)
    _check_dst_ports(packet)


def _check_tsport(packet):
    packet['sport'] = _handle_port(packet['tsport'])
    del packet['tsport']


def _check_ts_ud_ports(packet):
    _check_tsport(packet)
    _check_udport(packet)


def _check_tcp_ports(packet):
    _check_tsport(packet)
    _check_tdport(packet)


def _check_ts_dst_ports(packet):
    _check_tsport(packet)
    _check_dst_ports(packet)


def _check_src_ports(packet):
    port = 'sport'
    tport = _get_port_from_packet(packet, f't{port}')
    uport = _get_port_from_packet(packet, f'u{port}')
    packet[port] = tport if tport != -1 else uport


def _check_src_ud_ports(packet):
    _check_src_ports(packet)
    _check_udport(packet)


def _check_src_td_ports(packet):
    _check_src_ports(packet)
    _check_tdport(packet)


def _check_all_ports(packet):
    _check_src_ports(packet)
    _check_dst_ports(packet)


def _get_port_from_packet(packet, port):
    if port in packet:
        to_return = _handle_port(packet[port])
        del(packet[port])
    else:
        return -1
    return to_return


def _handle_ips(packet):
    for ip in _ip_mapping[_IP_SCORE]:
        if ip not in packet or any((not packet[ip], packet[ip] == '-')):
            packet[ip] = -1


def _handle_port(port):
    if port:
        return port
    return -1


def _handle_protocol(packet):
    if 'protocol' not in packet or any((not packet['protocol'], _cannot_be_int(packet['protocol']))):
        packet['protocol'] = -1
    else:
        packet['protocol'] = int(packet['protocol'])


def _dont_parse_ips_dont_parse_ports_dont_parse_protocol(packet):
    return packet


def _dont_parse_ips_dont_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    return packet


def _dont_parse_ips_parse_ports_dont_parse_protocol(packet):
    globals()[_port_mapping[_PORT_SCORE]](packet)
    return packet


def _dont_parse_ips_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    globals()[_port_mapping[_PORT_SCORE]](packet)
    return packet


def _parse_ips_dont_parse_ports_dont_parse_protocol(packet):
    _handle_ips(packet)
    return packet


def _parse_ips_dont_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    _handle_ips(packet)
    return packet


def _parse_ips_parse_ports_dont_parse_protocol(packet):
    globals()[_port_mapping[_PORT_SCORE]](packet)
    _handle_ips(packet)
    return packet


def _parse_ips_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    globals()[_port_mapping[_PORT_SCORE]](packet)
    _handle_ips(packet)
    return packet


def _combined_redis_key(packet, sensorname, to_add):
    protocol = _PROTOCOLS[str(packet['protocol'])]
    rKey = f"{sensorname}:{protocol}:{packet['timestamp']}"
    to_add["PROTOCOLS"].add(protocol)
    return rKey


def _simple_redis_key(packet, sensorname, _):
    return f"{sensorname}:{packet['timestamp']}"


def _set_json_timestamp(timestamp):
    int_part, dec_part = timestamp.split('.')
    intobj = datetime.datetime.fromtimestamp(float(int_part))
    return f'{intobj.strftime("%Y-%m-%d %H:%M:%S")}.{dec_part[:-3]}'


def _set_redis_timestamp(timestamp):
    int_part, _ = timestamp.split('.')
    intobj = datetime.datetime.fromtimestamp(float(int_part))
    return intobj.strftime("%Y%m%d")


if __name__ == '__main__':
    args = sys.argv
    standard_process(*args[1:])
