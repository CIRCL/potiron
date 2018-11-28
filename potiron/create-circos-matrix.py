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

import argparse
import redis
import sys
import os

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export data related to IP and MAC addresses into a matrix which will be used as data source for Circos')
    parser.add_argument('-s', '--source', type=str, nargs=1, help='Sensor used as data source (ex: "chp-5890-1")')
    parser.add_argument('-d', '--date', type=str, nargs=1, help='Date (day) of the informations to display (with the format YYYY-MM-DD)')
    parser.add_argument('-u', '--unix', type=str, nargs=1, help='Unix socket to connect to redis-server')
    parser.add_argument("-o","--outputdir", type=str, nargs=1, help="Output directory")
    args = parser.parse_args()

    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    
    if args.date is None:
        sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
        sys.exit(1)
    date = args.date[0]
    
    if args.unix is None:
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    
    if args.outputdir is None:
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
        if not outputdir.endswith('/'):
            outputdir = "{}/".format(outputdir)
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    
    redisKey = '{}*{}*'.format(source, date)
    mat = {}
    mactab = []
    
    for k in red.keys(redisKey):
        key = k.decode()
        ip = key.split('_')[1]
        mac = red.hget(key, 'rep_src_arp_mac')
        if mac is None:
            continue
        mac = mac.decode()
        mac = mac.replace(':','')
        if mac not in mactab:
            mactab.append(mac)
        if ip not in mat:
            mat[ip] = {}
        if mac in mat[ip]:
            mat[ip][mac] += 1
        else:
            mat[ip][mac] = 1
    
    output_file_name = '{}matrix_{}_{}.circos'.format(outputdir, source, date)
    with open(output_file_name, 'w') as f:
        f.write("mac\t")
        f.write("{}\n".format("\t".join(mactab)))
        for i in mat:
            f.write(i)
            for m in mactab:
                if m in mat[i]:
                    f.write("\t{}".format(mat[i][m]))
                else:
                    f.write("\t0")
            f.write("\n")
            
