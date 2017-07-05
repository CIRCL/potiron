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

import argparse
import json
import redis
import sys
import os
import potiron

# List of fields that are included in the json documents that should not
# be ranked
# FIXME Put this as argument to the program as this list depends on the
# documents that is introduced
non_index = ['', 'filename', 'sensorname', 'timestamp', 'packet_id']

def process_storage(filename, red, ck):
    # Check if file was already imported
    fn = os.path.basename(filename)
    if red.sismember("FILES", fn):
        sys.stderr.write('[INFO] Filename ' + fn + ' was already imported ... skip ...\n')
        sys.exit(0)

    f = open(filename, 'r')
    doc = json.load(f)
    f.close()

    # Record local dictionaries
    local_dicts = dict()
    rev_dics = dict()

    # Get sensorname assume one document per sensor name
    item = doc[0]
    bpf = item['bpf']
    # If redis key 'BPF' already exists
    if red.keys('BPF'):
        # Check is the current bpf is the same as the one previously used
        if not red.sismember('BPF', bpf):
            bpf_string = str(red.smembers('BPF'))
            sys.stderr.write('[INFO] BPF for the current data is not the same as the one used in the data already stored here : {}\n'.format(bpf_string[3:-2]))
            sys.exit(0)
    # On the other case, add the bpf in the key 'BPF'
    else:
        red.sadd('BPF', bpf)

    # If combined keys are used
    if ck is not None:
        ck_field = ck[0]
        # If redis key 'CK' already exists ...
        if red.keys('CK'):
            # ... BUT is set to 'Ńone', then combined keys are not used in the data already stored in redis
            if red.sismember('CK','None'):
                sys.stderr.write('[INFO] Combined key are not used in this redis dataset.\n')
                sys.exit(0)
            # ... BUT the field used for combined keys is not the same
            if not red.sscan('CK',0,'{}*'.format(ck_field))[1]:
                sys.stderr.write('[INFO] The field {} is not the one used for combined keys in this redis dataset.\n'.format(ck_field))
                sys.exit(0)
            # ... BUT the number of different values used is not the same
            if red.scard('CK') != len(ck) - 1:
                sys.stderr.write('[INFO] The number of different values used for combined keys you want is not the same as the one already defined in this redis dataset.\n')
                sys.exit(0)
            # ... BUT one of the values does not match the values already used
            for v in ck[1:]:
                member = '{}_{}'.format(ck_field, v)
                if not red.sismember('CK', member):
                    sys.stderr.write('[INFO] The {} {} is not included in redis combined keys for this dataset\n'.format(ck_field, v))
                    sys.exit(0)
            # if all the 4 previous tests are passed, then we know we are using the same combined keys
        # If redis key 'CK' does not exist ...
        else:
            # ... add each value in the key
            for v in ck[1:]:
                red.sadd('CK','{}_{}'.format(ck_field,v))
    # If combined key are not used, the key 'CK' should exist anyway, with the value 'None'
    else:
        # If redis key 'CK' already exists ...
        if red.keys('CK'):
            # ... BUT is not set to 'None', then combined keys are used in the data already stored in redis
            if not red.sismember('CK','None'):
                sys.stderr.write('[INFO] Combined key are used in this redis dataset.\n')
                sys.exit(0)
        # On the other case, we add it
        else:
            red.sadd('CK','None')

    red.sadd("FILES", fn)
    # FIXME documents must include at least a sensorname and a timestamp
    # FIXME check timestamp format
    sensorname = potiron.get_sensor_name(doc)
    lastday = None
    revcreated = False

    for di in doc:
        if di["type"] > potiron.DICT_LOWER_BOUNDARY:
            local_dicts[di["type"]] = di
        if di["type"] == potiron.TYPE_PACKET:
            if not revcreated:
                # FIXME if a json file was annotated twice the resulting json file
                # includes two dictionaries of the same type
                # Only the last one is considered
                rev_dics = potiron.create_reverse_local_dicts(local_dicts)
                revcreated = True
            key = sensorname
            if ck is not None:
                if ck_field == 'protocol':
                    if di['protocol'] == 6:
                        key += ":{}".format('tcp')
                    else:
                        key += ":{}".format('udp')
                else:
                    ck_val = di[ck_field]
                    if ck_val not in ck:
                        continue
                    key += ":{}_{}".format(ck_field,ck_val)
            timestamp = di['timestamp']
            (day, time) = timestamp.split(' ')
            day = day.replace('-', '')
            if day != lastday:
                red.sadd("DAYS", day)
            p = red.pipeline()
            for k in list(di.keys()):
                if k not in non_index and k != ck_field:
                    feature = di[k]
                    if k.startswith(potiron.ANNOTATION_PREFIX):
                        feature = potiron.translate_dictionaries(rev_dics, red, k, di[k])
                        # Create the links between annotations and their objects
                        idn = potiron.get_dictionary_id(k)
                        obj = potiron.get_annotation_origin(di, k)
                        if obj is not None and idn is not None:
                            kn = "AR_{}_{}".format(idn, obj)
                            p.set(kn, feature)
                    keyname = "{}:{}:{}".format(key,day,k)
                    p.sadd("FIELDS", k)
                    p.zincrby(keyname, feature, 1)
            # FIXME the pipe might be to big peridocially flush them
            p.execute()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Import json documents\
    into redis.')
    parser.add_argument('-i', '--input', type=str, nargs=1, help='Filename of a json document that should be imported.')
    parser.add_argument('-u', '--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-ck', '--combined_keys', type=str, nargs='+', help='Set if combined keys should be used')
    parser.add_argument('--reverse', action='store_false', help='Create global reverse dictionaries')

    args = parser.parse_args()
    if args.unix is None:
        sys.stderr.write('A unix socket must be specified\n')
        sys.exit(1)

    usocket = args.unix[0]

    red = redis.Redis(unix_socket_path=usocket)

    if args.combined_keys is None:
        ck = None
    else:
        ck = args.combined_keys

    if not args.reverse:
        potiron.create_reverse_global_dicts(red)
        potiron.infomsg("Created global reverse annotation dictionaries")
        sys.exit(0)

    if args.input is None:
        sys.stderr.write('A filename must be specified\n')
        sys.exit(1)
    filename = args.input[0]

    process_storage(filename, red, ck)
