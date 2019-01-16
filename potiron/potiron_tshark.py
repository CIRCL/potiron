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
import concurrent.futures
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


def process_files(red, files):
    potiron.json_fields = [json_field.decode() for json_field in red.lrange('JSON_FIELDS', 0, -1)]
    for key, value in red.hgetall('PARAMETERS').items():
        setattr(potiron, key.decode(), value.decode())
    potiron.redis_instance = red
    with concurrent.futures.ProcessPoolExecutor() as executor:
        for to_return in executor.map(globals()[_to_process[potiron.enable_json]], files):
            potiron.infomsg(to_return)


def _process_file(inputfile):
    red, to_add, to_incr, filename, sensorname = _get_data_structures(inputfile)
    if red.sismember("FILES", filename):
        return '[INFO] Filename %s was already imported ... skip ...\n' % inputfile
    # FIXME Users have to be carefull with the files extensions to not process data from capture files
    # FIXME (potiron-json-tshark module), and the same sample again from json files (potiron_redis module)

    # List of fields that are included in the json documents that should not be ranked
    # FIXME Put this as argument to the program as this list depends on the documents that is introduced
    proc = subprocess.Popen(potiron.cmd.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    to_add["FILES"].add(filename)

    lastday = None
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        packet['timestamp'] = _set_redis_timestamp(packet['timestamp'])
        timestamp = packet['timestamp']
        rKey = globals()[_ck_mapping[potiron.ck]](packet, sensorname, to_add)
        if timestamp != lastday:
            to_add["DAYS"].add(timestamp)
            lastday = timestamp
        for feature, value in packet.items():
            if feature not in non_index:
                redis_key = "%s:%s" % (rKey, feature)
                to_add["FIELDS"].add(feature)
                to_incr[redis_key][value] += 1
    p = red.pipeline()
    for key, values in to_add.items():
        p.sadd(key, *list(values))
    for redis_key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(redis_key, amount, value)
    p.execute()
    proc.wait()
    return 'Data from {} parsed.'.format(filename)


def _process_file_and_save_json(inputfile):
    red, to_add, to_incr, filename, sensorname = _get_data_structures(inputfile)
    if red.sismember("FILES", filename):
        return '[INFO] Filename %s was already imported ... skip ...\n' % inputfile
    # FIXME Users have to be carefull with the files extensions to not process data from capture files
    # FIXME (potiron-json-tshark module), and the same sample again from json files (potiron_redis module)

    # List of fields that are included in the json documents that should not be ranked
    # FIXME Put this as argument to the program as this list depends on the documents that is introduced
    proc = subprocess.Popen(potiron.cmd.format(inputfile), shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    to_add["FILES"].add(filename)
    allpackets = [{"type": potiron.TYPE_SOURCE, "sensorname": sensorname,
                   "filename": os.path.basename(inputfile), "bpf": potiron.tshark_filter}]
    lastday = None
    packet_id = 0
    for line in proc.stdout.readlines():
        packet = _create_packet(line)
        packet['timestamp'] = _set_redis_timestamp(packet['timestamp'])
        timestamp = packet['timestamp']
        rKey = globals()[_ck_mapping[potiron.ck]](packet, sensorname, to_add)
        if timestamp != lastday:
            to_add["DAYS"].add(timestamp)
            lastday = timestamp
        for feature, value in packet.items():
            if feature not in non_index:
                redis_key = "%s:%s" % (rKey, feature)
                to_add["FIELDS"].add(feature)
                to_incr[redis_key][value] += 1
        packet['timestamp'] = _set_json_timestamp(timestamp)
        packet['packet_id'] = packet_id
        packet['type'] = potiron.TYPE_PACKET
        packet['state'] = potiron.STATE_NOT_ANNOTATE
        allpackets.append(packet)
        packet_id += 1
    p = red.pipeline()
    for key, values in to_add.items():
        p.sadd(key, *list(values))
    for redis_key, values in to_incr.items():
        for value, amount in values.items():
            p.zincrby(redis_key, amount, value)
    p.execute()
    potiron.store_packet(potiron.rootdir, filename, json.dumps(allpackets))
    proc.wait()
    return 'Data from {} parsed and stored in json format.'.format(filename)


def _create_packet(line):
    line = line.decode().strip('\n')
    packet = {key: value for key, value in zip(potiron.json_fields, line.split(' '))}
    for special_field, value in special_fields.items():
        if special_field in packet and not packet[special_field]:
            packet[special_field] = value
    packet = globals()[potiron.to_call](packet)
    return packet


def _get_data_structures(inputfile):
    red = potiron.redis_instance
    to_add = defaultdict(set)
    to_incr = defaultdict(lambda: defaultdict(int))
    filename = os.path.basename(inputfile)
    # Name of the honeypot
    sensorname = potiron.derive_sensor_name(inputfile)
    return red, to_add, to_incr, filename, sensorname


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
    tdport = _get_port_from_packet(packet, 'tdport')
    udport = _get_port_from_packet(packet, 'udport')
    if all((tdport == -1, udport == -1)):
        packet['dport'] = -1
    else:
        packet['dport'] = tdport if tdport != -1 else udport


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
    tsport = _get_port_from_packet(packet, 'tsport')
    usport = _get_port_from_packet(packet, 'usport')
    if all((tsport == -1, usport == -1)):
        packet['sport'] = -1
    else:
        packet['sport'] = tsport if tsport != -1 else usport


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
    for ip in _ip_mapping[potiron.ip_score]:
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
    globals()[_port_mapping[potiron.port_score]](packet)
    return packet


def _dont_parse_ips_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    globals()[_port_mapping[potiron.port_score]](packet)
    return packet


def _parse_ips_dont_parse_ports_dont_parse_protocol(packet):
    _handle_ips(packet)
    return packet


def _parse_ips_dont_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    _handle_ips(packet)
    return packet


def _parse_ips_parse_ports_dont_parse_protocol(packet):
    globals()[_port_mapping[potiron.port_score]](packet)
    _handle_ips(packet)
    return packet


def _parse_ips_parse_ports_parse_protocol(packet):
    _handle_protocol(packet)
    globals()[_port_mapping[potiron.port_score]](packet)
    _handle_ips(packet)
    return packet


def _combined_redis_key(packet, sensorname, to_add):
    protocol = potiron.protocols[str(packet['protocol'])]
    rKey = "%s:%s:%s" % (sensorname, protocol, packet['timestamp'])
    to_add["PROTOCOLS"].add(protocol)
    return rKey


def _simple_redis_key(packet, sensorname, _):
    return "%s:%s" % (sensorname, packet['timestamp'])


def _set_json_timestamp(timestamp):
    int_part, dec_part = timestamp.split('.')
    intobj = datetime.datetime.fromtimestamp(float(int_part))
    return "%s:%s" % (intobj.strftime("%Y-%m-%d %H:%M:%S"), dec_part[:-3])


def _set_redis_timestamp(timestamp):
    int_part, _ = timestamp.split('.')
    intobj = datetime.datetime.fromtimestamp(float(int_part))
    return intobj.strftime("%Y%m%d")


if __name__ == '__main__':
    args = sys.argv
    process_file(*args[1:])
