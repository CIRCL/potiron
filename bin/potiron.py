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

import os
import datetime
import syslog

#Common functions related to importer scripts

#Generic filter for filtering out artefacts of honeypot operations
#TODO put this in a config file
bpffilter="not net 239.0.0.0/8 and not host 255.255.255.255"
PROTO_ICMP    = 1
PROTO_UDP     = 17
PROTO_TCP     = 6
PROTO_ICMP6   = 41
PROTO_UNKNOWN = 254
DEFAULTBULKBUFFER = 1000
logconsole=False

def get_file_struct(rootdir, filename, suffix="json"):
    try:
        if rootdir.endswith('/'):
            rootdir=rootdir[:-1]
        if suffix.startswith(".") == False:
            suffix="."+suffix

        f = os.path.basename(filename)
        f = f.replace('.cap.gz', '')
        (prefix,sensorname, instance, date) = f.split('-')
        obj = datetime.datetime.strptime(date,"%Y%m%d%H%M%S")
        out = obj.strftime("%Y/%m/%d")
        result = rootdir + os.sep + out + os.sep +f + suffix
        return result
    except ValueError,e:
        errormsg("get_file_struct." + str(e) + "\n")
        raise OSError("Do not know where to store the file "+filename)

def derive_sensor_name(filename):
    try:
        f = os.path.basename(filename)
        (prefix, sensorname, instance, date) = f.split('-')
        return prefix + "-" + sensorname + "-" + instance
    except ValueError:
        errormsg("Cannot derive sensor name form "+filename )

def infomsg(msg):
    if logconsole:
        syslog.openlog("potiron",syslog.LOG_PID | syslog.LOG_PERROR,
                       syslog.LOG_INFO)
    else:
        syslog.openlog("potiron",syslog.LOG_PID, syslog.LOG_INFO)
    syslog.syslog("[INFO] "+msg);

def errormsg(msg):
    if logconsole:
        syslog.openlog("potiron",syslog.LOG_PID | syslog.LOG_PERROR,
                       syslog.LOG_ERR)
    else:
        syslog.openlog("potiron",syslog.LOG_PID , syslog.LOG_ERR)

    syslog.syslog("[ERROR] "+ msg)

#Returns true if the program can be found and executed
#Returns false otherwise
def check_program(program):
    if program.find('/') >= 0:
        if os.path.isfile(program) and os.access(program,os.X_OK):
            return True
    #Search program in the path
    for i in os.environ['PATH'].split(':'):
        p = i + os.sep + program
        if os.path.isfile(p) and os.access(p, os.X_OK):
            return True
    return False

if __name__ == "__main__":
    print get_file_struct("/tmp","aaa")

