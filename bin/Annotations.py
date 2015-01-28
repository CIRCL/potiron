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
import datetime
import os
from potiron import get_file_struct
from potiron import errormsg

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

    def process_file(self):
        #FIXME read from config
        f = open(self.sourceFile,"r")
        docs = json.load(f)
        newdocs = []
        f.close()
        docs = self.handle_docs(docs)
        if self.directory is None:
            json.dump(docs, sys.stdout)
        else:
            #FIXME assume that always the same filename
            filename = None
            if len(docs) > 0:
                item = docs[0]
                if item.has_key("filename"):
                    filename = item["filename"]
            if filename is None:
                errormsg("Cannot store file as no filename was found")
                return
            fn = get_file_struct(self.directory, filename)
            t = fn.split("/")
            t.pop()
            d = "/".join(t)
            if os.path.exists(d) == False:
                os.makedirs(d)
            if os.path.exists(fn):
                #FIXME Merge files?
                errormsg("Do not overwrite file " + fn)
                return
            f = open(fn,"w")
            json.dump(docs,f)

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
