#!/usr/bin/python
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2015 Gerard Wagener
#    Copyright (C) 2015 CIRCL Computer Incident Response Center Luxembourg (smile gie)
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
import os
from PotironAnGeo import *
from PotironAnPDNS import *
import pprint
from potiron import get_file_struct
parser = argparse.ArgumentParser(description="Do all potiron annotations")
parser.add_argument("-r","--read", type=str, nargs=1,
help ="Json document that should be annotated")
parser.add_argument("-d","--directory", type=str, nargs=1, 
help="Directory containing the annotated files")
args = parser.parse_args()

f = sys.stdin
if args.read is not None:
    f = open(args.read[0],"r")
docs = json.load(f)
obj = AnnotateGeo()
pdns = AnnotatePDNS("127.0.0.1",8900)
fd = sys.stdout
if args.directory is not None:
    filename = None
    if args.read is None:
        filename = docs[0]["filename"]
    else:
        filename = args.read[0]

    fn = get_file_struct(args.directory[0], filename)
    t = fn.split('/')
    d = "/".join(t[0:-1])
    if os.path.exists(d) == False:
        os.makedirs(d)
    fd = open(fn,"w")
newdocs = []
for doc in docs:
    #Do all the annotations
    mod_doc = obj.annoate_doc(doc)
    mod_doc = pdns.annoate_doc(mod_doc)
    newdocs.append(mod_doc)
    
json.dump(newdocs,fd)
fd.close()

