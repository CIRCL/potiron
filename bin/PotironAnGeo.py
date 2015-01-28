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
import datetime
from unidecode import unidecode
from Annotations import Annotate

class AnnotateGeo(Annotate):

    def __init__(self):
        self.mfields = [ "ipsrc" , "ipdst", "packet_id", "timestamp",
                         "sensorname", "filename"]
        #Open the geoip database
        self.database    = "/usr/share/GeoIP/GeoIPCity.dat"
        self.gi = GeoIP.open(self.database,GeoIP.GEOIP_STANDARD)

        self.help=\
"""potiron-json-geo.py [-h] [-r filename] [-d directory] [-k]
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
#Function to annoate the data
    def annoate_doc(self, doc):
        g = self.gi.record_by_addr(doc["ipdst"])
        if g is not None:
            if g["city"] is not None:
                doc["dipcity"] = unidecode(g["city"])
            if g["country_name"] is not None:
                doc["dipcountry"] = unidecode(g["country_name"])

        g = self.gi.record_by_addr(doc["ipsrc"])
        if g is not None:
            if g["city"] is not None:
                doc["sipcity"] = unidecode(g["city"])
            if g["country_name"] is not None:
                doc["sipcountry"] = unidecode(g["country_name"])

        return doc

if __name__== "__main__":
    obj = AnnotateGeo()
    obj.handle_cli()
