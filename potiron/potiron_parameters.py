#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2018-2019 Christian Studer
#    Copyright (C) 2018-2019 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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

import potiron.potiron as potiron
import sys


potiron_parameters = {'ip_score': '3', 'json_fields': potiron.json_fields,
                      'port_score': '15', 'to_call': '_parse_ips_parse_ports_parse_protocol'}
_critical_redis_parameters = ('cmd', 'tshark_filter')


def _check_parameters(red, parameters):
    if red.keys('PARAMETERS'):
        _check_parameter_fields(red, parameters)
    else:
        red.hmset('PARAMETERS', parameters)


def _check_parameter_fields(red, parameters):
    red_parameters = {key.decode(): value.decode() for key, value in red.hgetall('PARAMETERS').items()}
    current_format = parameters.pop('format')
    redis_format = red_parameters.pop('format')
    if current_format != redis_format:
        sys.exit(f"[INFO] Format error: You want to store data in {current_format} format but this redis instance is used to store data in {redis_format} format.")
    if red_parameters != parameters:# and _deeper_parameter_fields_check(red, red_parameters, parameters):
        _deeper_parameter_fields_check(red, red_parameters, parameters)


def _check_standard_parameters(red, parameters):
    fields = parameters.pop('fields')
    if red.keys('FIELDS') and red.keys('PARAMETERS'):
        red_fields = set(field.decode() for field in red.lrange('FIELDS', 0, -1))
        if red_fields != set(fields):
            sys.exit(f'[INFO] Fields you are trying to ingest are not the same as the ones currently used: {red_json_fields}\n')
        _check_parameter_fields(red, parameters)
    else:
        red.rpush('FIELDS', *fields)
        red.rpush('JSON_FIELDS', *extract_json_fields(fields))
        red.hmset('PARAMETERS', parameters)


def _deeper_parameter_fields_check(red, red_params, current):
    error = ""
    change = ""
    for key, value in red_params.items():
        try:
            current_value = current[key]
        except KeyError:
            continue
        if value != current_value:
            if key in _critical_redis_parameters:
                error += f" - {key}:\n\t - current value: '{current_value}'\n\t - value saved in redis: '{value}'\n"
            else:
                red.hset("PARAMETERS", key, current_value)
                change += f" - {key}: {value} changed into {current_value}\n"
    if error:
        sys.exit(f"[INFO] Error with some of the critical parameters:\n{error}")
    if change:
        print(f"[INFO] Some not critical parameters have changed, the execution is not compromised but notice the following changes:\n{change}")


def extract_json_fields(fields):
    json_fields = []
    for field in fields:
        if field in ('tsport', 'usport', 'tdport', 'udport'):
            if field[1:] not in json_fields:
                json_fields.append(field[1:])
        elif field != 'timestamp':
            json_fields.append(field)
    return json_fields


def fetch_parameters(**parameters):
    red = parameters.pop('red')
    format = parameters['format']
    special_formats = ('isn', 'layer2')
    if format in special_formats:
        tshark_filter = getattr(potiron, f"{format}_tshark_filter")
        if parameters.get('tshark_filter'):
            tshark_filter += f" && {parameters.pop('tshark_filter')}"
            parameters['tshark_filter'] = tshark_filter
        parameters['cmd'] = _predefine_cmd(tshark_filter, getattr(potiron, f"{format}_tshark_fields"))
    else:
        field_filter = parameters.pop('field_filter', [])
        if field_filter:
            if 'frame.time_epoch' not in field_filter:
                field_filter.insert(0, 'frame.time_epoch')
            if 'ip.proto' not in field_filter:
                field_filter.insert(1, 'ip.proto')
        else:
            field_filter = potiron.tshark_fields
        tshark_filter = potiron.tshark_filter
        if parameters.get('tshark_filter'):
            tshark_filter += f" && {parameters.pop('tshark_filter')}"
            parameters['tshark_filter'] = tshark_filter
        parameters['cmd'] = _predefine_cmd(tshark_filter, field_filter)
        parameters.update(_get_current_fields(field_filter) if field_filter else potiron_parameters)
    _check_parameters(red, parameters) if format in special_formats else _check_standard_parameters(red, parameters)


def _get_current_fields(field_filter):
    parameters = {}
    try:
        current_fields = [potiron.json_fields[potiron.tshark_fields.index(field)] for field in field_filter]
    except ValueError:
        sys.exit(f"Wrong value for fields filter, choose in the following list: {', '.join(potiron.tshark_fields)}.\nAlternatively if you do not specify any field to filter on, all the fields in this list will be used.")
    parameters['fields'] = current_fields
    protocol = "parse" if 'protocol' in current_fields else 'dont_parse'
    port_score = _get_port_score(current_fields)
    parameters['port_score'] = str(port_score)
    ports = "dont_parse" if port_score == 0 else "parse"
    ip_score = _get_ip_score(current_fields)
    parameters['ip_score'] = str(ip_score)
    ips = "_dont_parse" if ip_score == 0 else "_parse"
    parameters['to_call'] = f"{ips}_ips_{ports}_ports_{protocol}_protocol"
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


def _predefine_cmd(tshark_filter, field_filter):
    filters = "-e {}".format(" -e ".join(field_filter))
    setup = f"-E header=n -E separator=/s -E occurrence=f -Y '{tshark_filter}' -r"
    end = "{} -o tcp.relative_sequence_numbers:FALSE"
    return f"tshark -n -q -Tfields {filters} {setup} {end}"
