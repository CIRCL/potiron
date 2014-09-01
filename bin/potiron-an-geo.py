#!/usr/bin/python
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
#
import getopt
import sys
import json
import pprint
import GeoIP
import redis
import datetime

def usage():
    print """potiron-json-geo.py [-h] [-r filename] [-d directory] [-k] 
                                 [-c config] [-i index] 

    -h Shows this screen
    -d directory Specify the directory where the files should be stored
    -k Sent log data also to console and not only to syslog
    -c Filename of the configuration file
    -i Put annotation data directly in the index instead of writing json
       files

INPUT FILES

This program reads json documents as input. The source IP addresses and
destination IP addresses are annotated with a Geo lookup  of each IP address.

The following fields are required in the input json files

KEY    VALUE

ipsrc  Source IP address in dotted decimal notation
ipdst  Destination IP address in dotted decimal notation


OUTPUT

The following fields are added to the json document

KEY           VALUE

sipcountry    Country of the source IP
sipcity       City of the source IP
dipcountry    Country of the Destination IP address
dipcity       City of the Destination IP address
"""

def annoate_doc(gi, doc):
    g = gi.record_by_addr(doc["ipdst"])
    if g is not None:
        if g["city"] is not None:
            doc["dipcity"] = g["city"]
        if g["country_name"] is not None:
            doc["dipcountry"] = g["country_name"]

    g = gi.record_by_addr(doc["ipsrc"])
    if g is not None:
        if g["city"] is not None:
            doc["sipcity"] = g["city"]
        if g["country_name"] is not None:
            doc["sipcountry"] = g["country_name"]

    return doc

def handle_docs(gi, docs):
    newdocs = [] 
    mfields = [ "ipsrc" , "ipdst", "packet_id", "timestamp", "sensorname", 
                "filename"]
    for doc in docs:
        complete = True
        for field in mfields:
            if field not in mfields:
                errormsg("Incomplete packet found in " + filename + "." +
                         str(doc)) 
                complete = False
        if complete == True:
            #FIXME the previous checks could be abstracted for all the annotation
            #programs
            doc = annoate_doc(gi,doc)
        #If the document is not complete or could not be annotated it should be
        #left intact
        newdocs.append(doc)
    return newdocs

def index_docs(red, docs):
    p = red.pipeline()
    #FIXME put in config
    bulksize = 100 # Multiplied by 4 as 4 keys are updated per document
    cnt = 0
    for doc in docs:
        date = doc[ "timestamp"].split(' ')[0].replace('-','')
        datetime.datetime.strptime(date, "%Y%m%d")
        if "sipcountry" in doc:
            k = doc["sensorname"] + ":" + date + ":" + "sipcountry"
            p.zincrby(k, doc["sipcountry"],1)
        if "sipcity" in doc:
            k = doc["sensorname"] + ":" + date + ":" + "sipcity"
            p.zincrby(k, doc["sipcity"],1)
        if "dipcountry" in doc:
            k = doc["sensorname"] + ":" + date + ":" + "dipcountry"
            p.zincrby(k, doc["dipcountry"],1)
        if "dipcity" in doc:
            k = doc["sensorname"] + ":" + date + ":" + "dipcity"
            p.zincrby(k, doc["dipcity"],1)
        cnt = cnt + 1
        if (cnt > 0) and (cnt % bulksize == 0):
            p.execute()
    p.execute()

def process_file(config, filename, shouldIndex, directory):
    if shouldIndex == False:
        if directory is None:
            raise OSError("No target directory was specified to store files\n")

    #FIXME read from config
    database    = "/usr/share/GeoIP/GeoIPCity.dat"
    red=redis.Redis(unix_socket_path="/tmp/redis.sock")
    gi = GeoIP.open(database,GeoIP.GEOIP_STANDARD)
    f = open(filename,"r")
    docs = json.load(f)
    newdocs = []
    f.close()
    docs = handle_docs(gi, docs)
    if shouldIndex == True:
        index_docs(red, docs)    

if __name__=='__main__':
    try:
        opts, args = getopt.getopt(sys.argv[1:], "hr:d:kc:i", ["help", "read",
                                   "directory", "konsole","config", "index"])
        shouldIndex = False
        sourceFile = None
        directory = None
        config = None
        for o, a in opts:
            if o in ("-h", "--help"):
                usage()
                sys.exit(0)
            if o in ("-i", "--index"):
                shouldIndex = True
            if o in ("-r", "--read"):
                sourceFile = a
            if o in ("-d", "--directory"):
                directory = a
            if o in ("-r","--read"):
                sourceFile = a 
            if o in ("-c","--config"):
                config = a

        if sourceFile is None:
            raise OSError("No source file was specified, abort")

        if shouldIndex == True and config is None:
            raise OSError("A config file must be specified to get the settings") 

        process_file(config, sourceFile, shouldIndex, directory) 
            
    except getopt.GetoptError,p:
        sys.stderr.write(str(p)+"\n")
        usage()
        sys.exit(1)
    except OSError,e:
        sys.stderr.write(str(e)+"\n")
        sys.exit(1)
