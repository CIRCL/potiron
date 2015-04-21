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
import potiron
import redis
import ipasn_redis as ipasn
import ConfigParser
class AnnotateASN(Annotate):

    def __init__(self, server, port):
        self.mfields = ["ipsrc" , "ipdst"]
        ipasn.hostname = server
        ipasn.port = port
        self.cache = dict()
        self.cacheid = 0
        self.help=\
"""PotironAnASN [-h] [-r filename] [-d directory] [-k]
                                 [-c config] [-i index] 

    -h Shows this screen
    -d directory Specify the directory where the files should be stored
    -k Sent log data also to console and not only to syslog
    -c Filename of the configuration file
    -i Put annotation data directly in the index instead of writing json
       files

INPUT FILES

This program reads json documents as input. The source IP addresses and
destination IP addresses are annotated with their ASN number.

The following fields are required in the input json files

KEY    VALUE

ipsrc  Source IP address in dotted decimal notation
ipdst  Destination IP address in dotted decimal notation


OUTPUT

The following fields are added to the json document

KEY           VALUE

ip_13_ipsrc   Pointer to the ASN annotation dictionary 
ip_13_ipdst   Pointer to the ASN annotation dictionary

CREATED dictionary
"""

    def get_asn(self, ipaddress,date):
        if self.cache.has_key(ipaddress):
            return self.cache[ipaddress]
        (asn,returndate) = ipasn.asn(ipaddress , date)
        #FIXME Cache is common between all annotations
        self.cacheid = self.cacheid + 1
        self.cache[ipaddress]  = (self.cacheid,asn)
        self.cache['type'] = potiron.TYPE_PDNS_DICT
        if returndate != date:
            #FIXME Not tested
            potiron.errormsg("Date mismatch between ASN database and encountered timestamp in packet capture. IP="+ipaddress+". Date="+date+" "+"Return date= "+returndate)
        return (self.cacheid, asn)

    def annoate_doc(self, doc):
        date = None
        if doc.has_key('state') == False:
            doc['state'] = 0
        #TODO test if already annoated
        d = "" 
        #Extract timestamp
        if doc.has_key('timestamp'):
            (date,time) = doc['timestamp'].split(' ')
            date=date.replace('-','')

        srcasn = 0
        if self.cache.has_key(doc['ipsrc']):
            srcid = self.cache[doc['ipsrc']]
        else:
            self.cacheid = self.cacheid + 1
            (srcasn,d) = ipasn.asn(doc['ipsrc'] , date)
            
        (aid, ip) = self.get_asn(doc["ipsrc"], date)
        if ip is not None:
            doc['a_'+str(potiron.TYPE_ASN_DICT)+'+_ipsrc'] = aid 
        (aid, ip) = self.get_asn(doc["ipdst"], date)
        if aid is not None:
            doc['a_'+str(potiron.TYPE_ASN_DICT)+'_ipdst'] =  aid
        doc["state"] = doc["state"] | potiron.STATE_ASN_AN

        return doc

if __name__== "__main__":
    pass
