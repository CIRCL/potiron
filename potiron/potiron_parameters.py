#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import potiron.potiron as potiron
import sys


potiron_parameters = {'ip_score': '3', 'json_fields': potiron.json_fields,
                      'port_score': '15', 'to_call': '_parse_ips_parse_ports_parse_protocol'}


def _check_parameters(red, parameters):
    json_fields = parameters.pop('json_fields')
    print(parameters)
    if red.keys('JSON_FIELDS') and red.keys('PARAMETERS'):
        red_json_fields = set(json_field.decode() for json_field in red.lrange('JSON_FIELDS', 0, -1))
        if red_json_fields != set(json_fields):
            sys.stderr.write('[INFO] Fields you are trying to ingest are not the same as the ones currently used: {}'.format(red_json_fields))
        red_parameters = {key.decode(): value.decode() for key, value in red.hgetall('PARAMETERS').items()}
        if red_parameters != parameters:
            sys.stderr.write('[INFO] Parameters you are using are not the same as the ones currently used: {}'.format(red_parameters))
    else:
        red.rpush('JSON_FIELDS', *json_fields)
        red.hmset('PARAMETERS', parameters)


def fetch_parameters(**parameters):
    field_filter = parameters.pop('field_filter', [])
    red = parameters.pop('red')
    if field_filter:
        if 'frame.time_epoch' not in field_filter:
            field_filter.insert(0, 'frame.time_epoch')
        if 'ip.proto' not in field_filter:
            field_filter.insert(1, 'ip.proto')
    tshark_filter = potiron.tshark_filter
    if parameters.get('tshark_filter'):
        tshark_filter += " && {}".format(parameters.pop('tshark_filter'))
    parameters['cmd'] = _predefine_cmd(field_filter, tshark_filter)
    parameters.update(_get_current_fields(field_filter) if field_filter else potiron_parameters)
    _check_parameters(red, parameters)


def _get_current_fields(field_filter):
    parameters = {}
    current_fields = []
    for field in field_filter:
        index = potiron.tshark_fields.index(field)
        current_fields.append((field, potiron.json_fields[index]))
    parameters['json_fields'] = current_fields
    protocol = "parse" if 'protocol' in current_fields else 'dont_parse'
    port_score = _get_port_score(current_fields)
    parameters['port_score'] = str(port_score)
    ports = "dont_parse" if port_score == 0 else "parse"
    ip_score = _get_ip_score(current_fields)
    parameters['ip_score'] = str(ip_score)
    ips = "_dont_parse" if ip_score == 0 else "_parse"
    parameters['to_call'] = "{}_ips_{}_ports_{}_protocol".format(ips, ports, protocol)
    return parameters


def _get_ip_score(fields):
    score = 0
    if 'ipsrc' in fields:
        score += 2
    if 'ipdst' in fields:
        score += 1
    return score


def _get_port_score(fields):
    score = 0
    if 'tsport' in fields:
        score += 8
    if 'usport' in fields:
        score += 4
    if 'tdport' in fields:
        score += 2
    if 'udport' in fields:
        score += 1
    return score


def _predefine_cmd(field_filter, tshark_filter):
    if not field_filter:
        field_filter = potiron.tshark_fields
    filters = "-e {}".format(" -e ".join(field_filter))
    setup = "-E header=n -E separator=/s -E occurrence=f -Y '{}' -r".format(tshark_filter)
    end = "{} -o tcp.relative_sequence_numbers:FALSE"
    return "tshark -n -q -Tfields {0} {1} {2}".format(filters, setup, end)
