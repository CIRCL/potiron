#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2017 Christian Studer
#    Copyright (C) 2017 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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

def field2string(field, potiron_path):
    field_strings={}
    with open("{}doc/fields".format(potiron_path), 'r') as p:
        for line in p.readlines():
            brut_val, real_val = line.split('\t')
            field_strings[brut_val] = real_val[:-1]
    field_string = ""
    field_in_file_name = ""
    for word in field_strings[field].split(" "):
        field_string += "{} ".format(word)
        field_in_file_name += "{}-".format(word)
    return field_string[:-1], field_in_file_name[:-1]


def create_dict(field, potiron_path):
    field_data = {}
    if field == "protocol":
        with open("{}doc/protocols".format(potiron_path),'r') as p:
            for line in p.readlines():
                val,n,_,_ = line.split('\t')
                field_data[n] = val
    elif field == "dport" or field == "sport":
        with open("{}doc/ports".format(potiron_path), 'r') as o:
            for line in o.readlines()[2:]:
                port,info = line.split('\t')
                nb = port.split('-')
                if len(nb) == 2:
                    for i in range(int(nb[0]),int(nb[1])+1):
                        if i in field_data:
                            continue
                        else:
                            field_data[i] = {}
                            field_data[i]['no_proto'] = info
                else:
                    if port in field_data:
                        continue
                    else:
                        field_data[port] = {}
                        field_data[port]['no_proto'] = info
        with open("{}doc/ports-ck".format(potiron_path),'r') as p:
            for line in p.readlines():
                port,proto,info = line.split('\t')
                nb = port.split('-')
                if len(nb) == 2 :
                    for i in range(int(nb[0]),int(nb[1])+1):
                        if i not in field_data:
                            field_data[i] = {}
                        if not proto:
                            field_data[i]["no_proto"] = info
                        else:
                            field_data[i][proto] = info
                else:
                    if port not in field_data:
                        field_data[port] = {}
                    if not proto:
                        field_data[port]["no_proto"] = info
                    else:
                        field_data[port][proto] = info
    return field_data


def def_legend(actual, protocol, field, field_string, field_data):
    if field == "protocol":
        if actual in field_data:
            return "{}, {}".format(actual, field_data[actual])
        else:
            return "{}, unknown {}".format(actual, field_string)
    elif field == "sport" or field == "dport":
        if actual in field_data:
            if protocol is not None:
                if protocol in field_data[actual]:
                    return "{}-{}, {}".format(actual, protocol, field_data[actual][protocol])
                else:
                    if "no_proto" in field_data[actual]:
                        return "{}-{}, {}".format(actual, protocol, field_data[actual]["no_proto"])
            else:
                if "no_proto" in field_data[actual]:
                    return "{}, {}".format(actual, field_data[actual]["no_proto"])
        return "{}-{}, unknown {}".format(actual, protocol, field_string)


def plot_annotation(field, potiron_path, fieldvalues, field_string, field_data):
    fieldvalues_string = ""
    star = []
    if field == "protocol":
        for v in fieldvalues:
            if v in field_data:
                fieldvalues_string += "{}, ".format(field_data[v])
            else:
                fieldvalues_string += "{}(unknown protocol), ".format(v)
    elif field == "dport" or field == "sport":
        for v in fieldvalues:
            value = v.split('-')
            prot = "no_proto"
            portvalue = value[0]
            if portvalue in star:
                continue
            if portvalue in field_data:
                if len(value) == 2:
                    prot = value[1]
                if prot in field_data[portvalue]:
                    fieldvalues_string += "{} ({}), ".format(v,field_data[portvalue][prot][:-1])
                elif prot == "*" or prot == "all":
                    star.append(portvalue)
                    if 'no_proto' in field_data[portvalue]:
                        fieldvalues_string += "{} ({}), ".format(portvalue,field_data[portvalue]['no_proto'][:-1])
                    else:
                        fieldvalues_string += "{} (unknown {}), ".format(portvalue,field_string)
                else:
                    if 'no_proto' in field_data[portvalue]:
                        fieldvalues_string += "{} ({}), ".format(v,field_data[portvalue]['no_proto'][:-1])
                    else:
                        fieldvalues_string += "{} (unknown {}), ".format(v,field_string)
            else:
                if len(value) == 2:
                    if value[1] == "*":
                        star.append(portvalue)
                fieldvalues_string += "{} (unknown {}), ".format(portvalue,field_string)
    else:
        for v in fieldvalues:
            fieldvalues_string += "{}, ".format(v)
    return fieldvalues_string


def bubble_annotation(field, field_string, value, potiron_path, prot):
    if field == "protocol":
        with open("{}doc/protocols".format(potiron_path),'r') as p:
            for line in p.readlines():
                l = line.split('\t')
                if value == l[1]:
                    return " - {}".format(l[0])
        return " - unknown protocol"
    elif field == "dport" or field == "sport":
        with open("{}doc/ports-ck".format(potiron_path),'r') as p:
            for line in p.readlines():
                l = line.split('\t')
                if value == l[0]:
                    if prot is None:
                        return " - {}".format(l[2][:-1])
                    else:
                        if prot == l[1]:
                            return " - {}".format(l[2][:-1])
        return (" - unknown {}".format(field_string))
    else:
        return
