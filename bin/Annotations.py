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

class Annotate(object):

    # The following attributes are needed
    # - self.help contains the description of the program 
    # - A list of mandatory fields (self.mfields)

    def usage(self):
        print self.help

    #This function should be overridden
    def annoate_doc(self, doc):
        pass

    def handle_docs(self, docs):
        newdocs = [] 
        for doc in docs:
            complete = True
            for field in self.mfields:
                if field not in self.mfields:
                    errormsg("Incomplete packet found in " + filename + "." +
                         str(doc)) 
                    complete = False
            if complete == True:
                doc = self.annoate_doc(doc)
            #If the document is not complete or could not be annotated it should be
            #left intact
            newdocs.append(doc)
        return newdocs

    def index_docs(self, red, docs):
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

    def process_file(self):
        if self.shouldIndex == False:
            if self.directory is None:
                raise OSError("No target directory was specified to store files\n")

        #FIXME read from config
        red=redis.Redis(unix_socket_path="/tmp/redis.sock")
        gi = GeoIP.open(self.database,GeoIP.GEOIP_STANDARD)
        f = open(self.sourceFile,"r")
        docs = json.load(f)
        newdocs = []
        f.close()
        docs = self.handle_docs(docs)
        if self.shouldIndex == True:
            self.index_docs(red, docs)    

    def handle_cli(self):
        try:
            opts, args = getopt.getopt(sys.argv[1:], "hr:d:kc:i", ["help", 
                             "read", "directory", "konsole","config", "index"])
            self.shouldIndex = False
            self.sourceFile = None
            self.directory = None
            self.config = None
            for o, a in opts:
                if o in ("-h", "--help"):
                    self.usage()
                    sys.exit(0)
                if o in ("-i", "--index"):
                    self.shouldIndex = True
                if o in ("-d", "--directory"):
                    self.directory = a
                if o in ("-r","--read"):
                    self.sourceFile = a 
                if o in ("-c","--config"):
                    self.config = a

            if self.sourceFile is None:
                raise OSError("No source file was specified, abort")

            if self.shouldIndex == True and self.config is None:
                raise OSError("A config file must be specified to get the settings") 

            self.process_file() 
            
        except getopt.GetoptError,p:
            sys.stderr.write(str(p)+"\n")
            usage()
            sys.exit(1)
        except OSError,e:
            sys.stderr.write(str(e)+"\n")
            sys.exit(1)

if __name__=='__main__':
    mfields = [ "ipsrc" , "ipdst", "packet_id", "timestamp", "sensorname", 
                "filename"]
    an = Annotate("config.cfg", mfields)
    an.handle_cli() 
