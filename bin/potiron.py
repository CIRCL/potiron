#!/usr/bin/env python3
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2014 Gerard Wagener
#    Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import os
import datetime
import syslog
import sys

# Common functions related to importer scripts

# Generic filter for filtering out artefacts of honeypot operations
# TODO put this in a config file
bpfilter = "not net 239.0.0.0/8 and not host 255.255.255.255"
tshark_filter = "ip.dst ne 255.255.255.255"
isn_tshark_filter = "{} && ip.proto eq 6".format(tshark_filter)
tshark_fields = ['frame.time_epoch','ip.len','ip.proto','ip.src','ip.dst',
                 'ip.ttl','ip.dsfield','tcp.srcport','udp.srcport','tcp.dstport',
                 'udp.dstport','tcp.seq','tcp.ack','icmp.code','icmp.type']
json_fields = ['timestamp','length','protocol','ipsrc','ipdst','ipttl','iptos',
               'tsport','usport','tdport','udport','tcpseq','tcpack','icmpcode',
               'icmptype']
PROTO_ICMP = 1
PROTO_UDP = 17
PROTO_TCP = 6
PROTO_ICMP6 = 41
PROTO_UNKNOWN = 254
DEFAULTBULKBUFFER = 1000

# Object types that are included in the json documents
TYPE_SOURCE = 1
TYPE_PACKET = 2

# Types that identify annotation objects should have a value larger than
# 10 such that simple if clause > 10 is enough to distinguish between
# data objects and annotation objects
DICT_LOWER_BOUNDARY = 10
TYPE_GEO_DICT = 11
TYPE_PDNS_DICT = 12
TYPE_ASN_DICT = 13
TYPE_UPPER_BOUNDARY = 13

# Object states that can be merged using OR
STATE_NOT_ANNOTATE = 0
STATE_TO_ANNOTATE = 1
STATE_GEO_AN = 2
STATE_PDNS_AN = 4
STATE_ASN_AN = 16

ANNOTATION_PREFIX = "a_"

logconsole = True

year = {'01': 'January', '02': 'February', '03': 'March', '04': 'April', '05': 'May', '06': 'June',
        '07': 'July', '08': 'August', '09': 'September', '10': 'October', '11': 'November', '12': 'December'}

current_path = os.path.dirname(os.path.realpath(__file__))
potiron_path = current_path[:-3]

def get_file_struct(rootdir, filename, suffix="json"):
    try:
        if rootdir.endswith('/'):
            rootdir = rootdir[:-1]
        if not suffix.startswith("."):
            suffix = "." + suffix

        f = os.path.basename(filename)
        f = f.replace('.cap.gz', '')
        f = f.replace('.json', '')
        prefix, sensorname, instance, date = f.split('-')
        obj = datetime.datetime.strptime(date, "%Y%m%d%H%M%S")
        out = obj.strftime("%Y/%m/%d")
        result = rootdir + os.sep + out + os.sep + f + suffix
        return result
    except ValueError as e:
        errormsg("get_file_struct." + str(e) + "\n")
        raise OSError("Do not know where to store the file " + filename)


def derive_sensor_name(filename):
    try:
        f = os.path.basename(filename)
        (prefix, sensorname, instance, date) = f.split('-')
        return prefix + "-" + sensorname + "-" + instance
    except ValueError:
        errormsg("Cannot derive sensor name form " + filename)


def infomsg(msg):
    if logconsole:
        syslog.openlog("potiron", syslog.LOG_PID | syslog.LOG_PERROR,
                       syslog.LOG_INFO)
    else:
        syslog.openlog("potiron", syslog.LOG_PID, syslog.LOG_INFO)
    syslog.syslog("[INFO] " + msg)


def errormsg(msg):
    if logconsole:
        syslog.openlog("potiron", syslog.LOG_PID | syslog.LOG_PERROR,
                       syslog.LOG_ERR)
    else:
        syslog.openlog("potiron", syslog.LOG_PID, syslog.LOG_ERR)

    syslog.syslog("[ERROR] " + msg)


# Returns true if the program can be found and executed
# Returns false otherwise
def check_program(program):
    if program.find('/') >= 0:
        if os.path.isfile(program) and os.access(program, os.X_OK):
            return True
    # Search program in the path
    for i in os.environ['PATH'].split(':'):
        p = i + os.sep + program
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return True
    return False


def get_sensor_name(doc):
    for obj in doc:
        if "type" in obj:
            if obj["type"] == TYPE_SOURCE:
                if "sensorname" in obj:
                    return obj["sensorname"]
    return None

def define_protocols(path):
    protocols = {}
    with open(path, 'r') as prots:
        for prot in prots.readlines():
            l = prot.split('\t')
            protocols[l[1]] = l[0]
        return protocols


# Save the output json file
def store_packet(rootdir, pcapfilename, obj):
    if rootdir is not None:
        jsonfilename = get_file_struct(rootdir, pcapfilename)
        with open(jsonfilename, "w") as f:
            f.write(obj)
        infomsg("Created filename " + jsonfilename)
        return jsonfilename
    else:
        sys.stdout.write(obj)


# Create the output directory and file if it does not exist
def create_dirs(rootdir, pcapfilename):
    jsonfilename = get_file_struct(rootdir, pcapfilename)
    d = os.path.dirname(jsonfilename)
    try:
        if not os.path.exists(d):
            os.makedirs(d)
    except OSError:
        pass


# In order to save space in json documents the annotations are not repeated
# each time. Just a pure local numeric ID is stored. These numeric ids are
# stored in local dictionaries. This function takes all dictionaries and
# creates a dictionary to lookup an id in a local dictionary
def create_reverse_local_dicts(dicts):
    rdicts = dict()
    for typ in list(dicts.keys()):
        if typ not in rdicts:
            rdicts[typ] = dict()
        for key in dicts[typ]:
            if key != "type":
                (aid, an) = dicts[typ][key]
                rdicts[typ][aid] = an
    return rdicts


# The json creation process should be completely independant for parallel
# processing.  The identifiers are only locally known.
# The following situtation my arise
#   Annotation A has ID 1
# In an other instance  the
#   Annotation A has the ID 2
# Hence One annotation has two different identifiers which should be avoided
# by merging them centrally in redis
def translate_dictionaries(rev_dicts, red, key, localvalue):
    # If the new value cannot be identified -1 is returned
    new_id = -1
    if key.startswith("a_"):
        try:
            t = key.split('_')
            dt = int(t[1])
            if dt not in rev_dicts:
                raise KeyError("Dictionary type {} is not known".format(dt))
            if localvalue not in rev_dicts[dt]:
                raise KeyError("Local value in dictionary {}: {} is unknown".format(dt, localvalue))
            new_value = rev_dicts[dt][localvalue]
            # TODO check in local cache
            name = "_".join(t[2:])
            k = "RT_a_{}_{}".format(dt, name)
            # Remembers the annotation keys for later enumeration for generating
            # the reverse keys
            red.sadd("RTK", k)
            new_id = red.hget(k, new_value)
            if new_id is None:
                # Create new identifier
                ki = "RTI_{}_{}".format(dt, name)
                # In the meantime another process could have created an
                # identifier for the key X. So the key X might have multiple
                # identifiers. Therefore, update only the identifier if it
                # does not exist
                # FIXME not tested
                new_id = red.incr(ki)
                if red.hsetnx(k, new_value, new_id) == 0:
                    # Someone else created already an id use this one
                    new_id = red.hget(k, new_value)
                # TODO Create reverse keys
        except IndexError as e:
            errormsg("translate_dictionaries: Invalid key notation. key=" + key)
        except KeyError as e:
            errormsg("translate_dictionaries: {}".format(e))

    return new_id


# The global reverse dictionary should be created by a single process in order
# to avoid race conditions
# FIXME This does not scale if the number of keys becomes too large
def create_reverse_global_dicts(red):
    for k in red.smembers("RTK"):
        kr = k.replace("RT_a_", "TR_a_")
        di = red.hgetall(k)
        for k in list(di.keys()):
            v = di[k]
            red.hset(kr, v, k)


# Extract the origin of an annotation key does the lookup in the document
# and return the corresponding value
# Example:
#         a_12_ipsrc ->  5
#         RT_a_12_ipsrc [www.circl.lu] -> 5
#         TR_a_12_isrc [5] -> www.circl.lu
# Creates the relationship 149.13.33.4 -> 5
def get_annotation_origin(doc, k):
    try:
        t = k.split("_")
        probe = t[2]
        return doc[probe]
    except IndexError:
        errormsg("Key is to incomplete {}\n".format(k))
    except KeyError:
        errormsg("Corresponding key not found for {}\n".format(k))
    return None


# Returns the dictionary identifier from a given key
def get_dictionary_id(k):
    try:
        t = k.split('_')
        return int(t[1])
    except IndexError:
        errormsg("Could not extract dictionary key from " + k)
    except ValueError:
        errormsg("Could not dictionary key from " + k)
    return None


# Returns a list of annotations corresponding to the key feature identified
# with its name
# example get_annotations(redis_instance, "192.168.1.1", "ipsrc")
def get_annotations(red, feature, name):
    out = []
    # Probe all the dictionaries
    for i in range(DICT_LOWER_BOUNDARY, TYPE_UPPER_BOUNDARY):
        k = "AR_{}_{}".format(i, feature)
        idn = red.get(k)
        if idn is not None:
            kd = "TR_a_{}_{}".format(i, name)
            value = red.hget(kd, idn)
            if value is not None:
                out.append(value)
            else:
                errormsg("Reverse keys not created?. No data for " + kd)
    return out

if __name__ == "__main__":
    print(get_file_struct("/tmp", "aaa"))
