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
#
import requests
import json
from Annotations import Annotate
import potiron
class AnnotatePDNS(Annotate):

    def __init__(self,server, port):
        self.server = server
        self.port = port
        self.url = "http://"+server+":"+str(port)+"/query/"
        self.mfields = [ "ipsrc", "ipdst", "packet_id", "timestamp",
                         "sensorname", "filename"]
        self.help = "NYI"
        self.cache = dict()
        self.cacheid = 0
        self.cache['type'] = potiron.TYPE_PDNS_DICT

    def get_rrnames(self, ipaddress):
        if self.cache.has_key(ipaddress):
            return self.cache[ipaddress]
        names = []
        rrnames = dict()
        r = requests.get(self.url  +  ipaddress)
        if r.status_code == 200:
            lines = r.content.split('\n')
            for sr in lines:
                if sr != "":
                    obj = json.loads(sr)
                    if obj.has_key('rrname'):
                         rrnames[obj['rrname']] = 1
            names = rrnames.keys()
            names.sort()
        r =  ",".join(names)
        self.cacheid = self.cacheid + 1
        self.cache[ipaddress] = (self.cacheid, r)
        return (self.cacheid, r)

    def annoate_doc(self, doc):
        (rid,name) = self.get_rrnames(doc["ipsrc"])
        if name != "":
            doc["ipsrc_pdns"] = rid
        (rid,name) = self.get_rrnames(doc["ipdst"])
        if name != "":
            doc["ipdst_pdns"] = rid
        doc["state"] = doc["state"] | potiron.STATE_PDNS_AN
        return doc

    #Remove all the IP addresses that had no PDNS results
    def compact_cache(self):
        for key in self.cache.keys():
            if key is not "type":
                (rid, rrname) = self.cache[key]
                if rrname is "":
                    del self.cache[key]

if __name__ == "__main__":
    #FIXME put in config file
    obj = AnnotatePDNS("127.0.0.1",8900)
    obj.handle_cli()
