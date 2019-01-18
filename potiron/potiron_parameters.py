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


def _check_isn_parameters(red, parameters):
    if red.keys('PARAMETERS'):
        _check_parameter_fields(red, parameters)
    else:
        red.hmset('PARAMETERS', parameters)


def _check_parameters(red, parameters, isn):
    if isn:
        _check_isn_parameters(red, parameters)
    else:
        _check_standard_parameters(red, parameters)


def _check_parameter_fields(red, parameters):
    red_parameters = {key.decode(): value.decode() for key, value in red.hgetall('PARAMETERS').items()}
    if red_parameters != parameters and _deeper_parameter_fields_check(red_parameters, parameters):
        sys.stderr.write(f'[INFO] Parameters you are using are not the same as the ones currently used: {red_parameters}'
        sys.exit(1)


def _check_standard_parameters(red, parameters):
    json_fields = parameters.pop('json_fields')
    if red.keys('JSON_FIELDS') and red.keys('PARAMETERS'):
        red_json_fields = set(json_field.decode() for json_field in red.lrange('JSON_FIELDS', 0, -1))
        if red_json_fields != set(json_fields):
            sys.stderr.write(f'[INFO] Fields you are trying to ingest are not the same as the ones currently used: {red_json_fields}')
            sys.exit(1)
        _check_parameter_fields(red, parameters)
    else:
        red.rpush('JSON_FIELDS', *json_fields)
        red.hmset('PARAMETERS', parameters)


def _deeper_parameter_fields_check(red, current):
    field = 'enable_json'
    red_ej = red.pop(field)
    current_ej = current.pop(field)
    to_return = (red == current)
    red[field] = red_ej
    current[field] = current_ej
    return to_return


def fetch_parameters(**parameters):
    red = parameters.pop('red')
    isn = parameters['isn']
    if isn:
        tshark_filter = potiron.isn_tshark_filter
        if parameters.get('tshark_filter'):
            tshark_filter += f" && {parameters.pop('tshark_filter')}"
        parameters['cmd'] = _predefine_cmd(tshark_filter)
    else:
        field_filter = parameters.pop('field_filter', [])
        if field_filter:
            if 'frame.time_epoch' not in field_filter:
                field_filter.insert(0, 'frame.time_epoch')
            if 'ip.proto' not in field_filter:
                field_filter.insert(1, 'ip.proto')
        tshark_filter = potiron.tshark_filter
        if parameters.get('tshark_filter'):
            tshark_filter += f" && {parameters.pop('tshark_filter')}"
        parameters['cmd'] = _predefine_cmd(tshark_filter, field_filter)
        parameters.update(_get_current_fields(field_filter) if field_filter else potiron_parameters)
    parameters['isn'] = str(isn)
    _check_parameters(red, parameters, isn)


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


def _predefine_cmd(tshark_filter, field_filter=None):
    if field_filter is None:
        field_filter = potiron.isn_tshark_fields
    else:
        if not field_filter:
            field_filter = potiron.tshark_fields
    filters = "-e {}".format(" -e ".join(field_filter))
    setup = f"-E header=n -E separator=/s -E occurrence=f -Y '{tshark_filter}' -r"
    end = "{} -o tcp.relative_sequence_numbers:FALSE"
    return f"tshark -n -q -Tfields {filters} {setup} {end}"
