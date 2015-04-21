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
from PotironAnASN import *
import pprint
from potiron import get_file_struct
from potiron import errormsg
import ConfigParser

parser = argparse.ArgumentParser(description="Do all potiron annotations")
parser.add_argument("-r","--read", type=str, nargs=1,
help ="Json document that should be annotated")
parser.add_argument("-d","--directory", type=str, nargs=1, 
help="Directory containing the annotated files")
parser.add_argument("-c", "--config", type=str, nargs=1,
help="Config file")

args = parser.parse_args()
if args.config is None:
    errormsg("A config file must be specified")
    sys.exit(1)
#Load config file
config = ConfigParser.ConfigParser()
config.readfp(open(args.config[0], 'r'))
#Access the fields if not exits throw excpetion
#FIXME implement cleaner error handling
config.get("pdns","server")
config.getint("pdns","port")
config.get("ipasn","server")
config.getint("ipasn","port")
f = sys.stdin
if args.read is not None:
    f = open(args.read[0],"r")
docs = json.load(f)
#FIXME Mandatory fields are not checked
obj = AnnotateGeo()
pdns = AnnotatePDNS(config.get("pdns","server"),config.getint("pdns" ,"port"))
asn = AnnotateASN(config.get("ipasn","server"), config.getint("ipasn","port"))
fd = sys.stdout
if args.directory is not None:
    filename = None
    if args.read is None:
        if len(docs) > 0:
            if docs[0].has_key("filename") == False:
                sys.exit(0)
            filename = docs[0]["filename"]
        else:
            #When no filename can be extracted abort
            sys.exit(0)
    else:
        filename = args.read[0]

    fn = get_file_struct(args.directory[0], filename)
    t = fn.split('/')
    d = "/".join(t[0:-1])
    #When processing in parallel the directory could have been created
    #Between the directory test and makedirs
    try:
        if os.path.exists(d) == False:
            os.makedirs(d)
    except OSError,e:
        if e.errno != 17:
            #Something else happened propagate exception
            raise OSError(e)
        potiron.infomsg("Someone else created the directory")
    fd = open(fn,"w")
newdocs = []
for doc in docs:
    #If the mandatory fields are not present the document should be left
    #intact
    mod_doc = doc
    if doc.has_key('type'):
        if doc['type'] == potiron.TYPE_PACKET:
            #Do all the annotations
            if obj.check_mandatory_fields(doc):
                mod_doc = obj.annoate_doc(doc)
            if pdns.check_mandatory_fields(doc):
                mod_doc = pdns.annoate_doc(mod_doc)
            newdocs.append(mod_doc)

pdns.compact_cache()
#Add Caches
#Do not add empty dictionaries
if len(pdns.cache) > 1:
    newdocs.insert(0,pdns.cache)
json.dump(newdocs,fd)
fd.close()

