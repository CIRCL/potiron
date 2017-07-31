#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import redis
import argparse
import sys
import os
import calendar
import potiron
import bokeh_month
from potiron_graph_annotation import field2string,bubble_annotation


MAXVAL = sys.maxsize


# Definition of the output file name
def output_name(source, field, date, dest):
    data_part = "{}{}_{}".format(dest, source, field)
    date_part = "{}-{}".format(date[0:4], date[4:6])
    return data_part, date_part


# Search the scores in the ranged list of values, and put them in the disctionary of scores
def process_score(red, redisKey, score, general_score, skip):
    # For each value ranged in decreasing order
    for v in red.zrevrangebyscore(redisKey,MAXVAL,0):
        countValue = red.zscore(redisKey,v)
        val = v.decode()
        if val in skip : # If the current value has to be skipped, go to the next iteration of the loop
            continue
        if val in score: # If the current value is already present in the list of values, increment the score with the current score
            score[val]+=countValue
        else: # On the other  case, add the value with its score in the list
            score[val]=countValue
        if general_score is not None:
            if val in general_score: # same operations for the dictionary containing the values for all the protocols
                general_score[val]+=countValue
            else:
                general_score[val]=countValue


# Sort the scores for the entire month and write them with their corresponding values in the .csv file
def process_file(score, name, prot):
    # Sort the complete list of values for the month by score
    res = list(sorted(score, key=score.__getitem__, reverse=True))
    l = 0
    values = []
    for s in res:
        # If the current value is not one that should be skipped, increment the number of values to include in the chart
        if s not in args.skip:
            values.append(s)
            l += 1
        # When the limit value is reached, we don't need to increment anymore, we break the loop
        if l >= limit:
            break
     # Write all the values and their scores into the csv datafile
    with open("{}.csv".format(name),'w') as f:
        f.write("id,value\n")
        for v in values :
            val = bubble_annotation(field,field_string,v,potiron_path,prot)
            f.write("{}{},\n".format(v,val))
            f.write("{}{},{}\n".format(v,val,int(score[v])))
    return values


# Call the bokeh function to create a plot with the scores of the "field" "v" in the current month defined by "date"
def generate_links(red, source, field, date, v, outputdir, logofile, namefile, wp):
    n = namefile.split('/')
    name = n[-1].split('_')
    bokeh_filename = ''
    for s in n[:-1]:
        bokeh_filename += '{}/'.format(s)
    if wp:
        bokeh_filename += '{}_{}_{}_with-protocols_{}.html'.format(name[0],name[3],name[1],v.split('-')[0])
    else:
        bokeh_filename += '{}_{}_{}_{}.html'.format(name[0],name[2],name[1],v)
    print(bokeh_filename)
    if not os.path.exists(bokeh_filename):
        bokeh_month.process_file(red, source, field, date, [v], outputdir, logofile, False)
        

# Parameters parser
parser = argparse.ArgumentParser(description='Export one month data from redis')
parser.add_argument("-s","--source", type=str, nargs=1, help='Sensor used as source (ex: "chp-5890-1")')
parser.add_argument("-d","--date", type=str, nargs=1, help='Date of the informations to display (with the format YYYY-MM)')
parser.add_argument("-f","--field", type=str, nargs=1, help='Field used (ex: "dport")')
parser.add_argument("-l","--limit", type=int, nargs=1, help="Limit of values to export - default 20")
parser.add_argument("--skip", type=str, default=None, action="append", help="Skip a specific value")
parser.add_argument("-o","--outputdir", type=str, nargs=1, help="Output directory")
parser.add_argument("-u","--unix", type=str, nargs=1, help='Unix socket to connect to redis-server.')
parser.add_argument("--links", action='store_true', help="Use this parameter if you want to directly create the bokeh plots usefull to have all the links working")
parser.add_argument("-g", "--generate", action='store_true', help="Auto generate the graphs, so you do not need to launch the command by your own")
parser.add_argument('--logo', type=str, nargs=1, help='Path of the logo file to display')
parser.add_argument('-p', '--without_protocols', action='store_false', help="Use this parameter for example if you want to generate a graph with links pointing to a field which is not plotted with the different protocols\
                    (i.e the specific field with all protocols together in only one line).")
args = parser.parse_args()

if args.source is None: # Source sensor
    source = "potiron"
else:
    source = args.source[0]

if args.date is None: # Define the date of the data to select
    sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM')
    sys.exit(1)
date = args.date[0].replace("-","")

if args.unix is None: # Unix socket to connect to redis-server
    sys.stderr.write('A Unix socket must be specified.\n')
    sys.exit(1)
usocket = args.unix[0]
red = redis.Redis(unix_socket_path=usocket)

# Define the fields available in redis
members=""
tab_members=[]
for i in red.smembers('FIELDS'):
    val = i.decode()
    members = members + val + ", "
    tab_members.append(val)
members=members[:-2]

# If no field is given in parameter, or if the field given is not in the fields in redis, the module stops
if args.field is None:
    sys.stderr.write("A field must be specified.\n")
    sys.exit(1)
if args.field[0] not in tab_members:
    sys.stderr.write('The field you chose does not exist.\nChoose one of these : {}.\n'.format(members))
    sys.exit(1)
field = args.field[0]

if args.limit is None: # Limit number of bubbles to display in the chart
    limit = 10
else:
    limit = args.limit[0]

if args.skip is None: # Values to skip
    skip = ['-1']
else:
    skip = args.skip

if args.outputdir is None: # Destination directory for the output file
    outputdir = "./out/"
else:
    outputdir = args.outputdir[0]
    if not outputdir.endswith('/'):
        outputdir = "{}/".format(outputdir)
if not os.path.exists(outputdir):
    os.makedirs(outputdir)

with_protocols = args.without_protocols # Defines if scores should be displayed for protocols together or for each protocol
if red.sismember("CK", "YES"): # Defines if combined keys are used in the current redis database
    ck = True
else:
    if with_protocols: # If combined keys are not used, it is not possible to display scores for each protocol,
        with_protocols = False # and they will be displayed for protocols together
        potiron.infomsg('You did not choose to use the parameter "without_protocols" but your redis database is not currently supporting combined keys.\
                        It will continue anyway without specifying each protocol..')
    ck = False
 
links = args.links # Defines if bokeh plots should be processed for each value in bubbles

gen = args.generate # Defines if charts should be auto-generated from datafiles

potiron_path = potiron.potiron_path # Project directory
current_path = potiron.current_path # Module directory

if args.logo is None: # Define path of circl logo, based on potiron path
    logofile = "{}doc/circl.png".format(potiron_path)
else:
    logofile = args.logo[0]

# Definition of the protocol values
protocols = red.smembers("PROTOCOLS")
# Definition of the strings containing the informations of the field, used in the legend and the file name
field_string, field_in_file_name = field2string(field, potiron_path)
namefile_data, namefile_date = output_name(source,field_in_file_name,date,outputdir)
days = calendar.monthrange(int(date[0:4]),int(date[4:6]))[1]
if with_protocols: # variable is True, the parameter has not been called, so we process data for each protocol
    at_least_one = False
    general_score = {}
    for prot in protocols: 
        protocol = prot.decode()
        score={}
        exists = False
        keys = red.keys("{}:{}:{}*:{}".format(source,protocol,date,field))
        for k in sorted(keys): # For each day of the month
            redisKey = k.decode()
            exists = True
            process_score(red, redisKey, score, general_score, skip)  # update the complete scores
        if exists:
            at_least_one = True
            namefile = "{}_{}_{}".format(namefile_data,protocol,namefile_date)
            val = process_file(score, namefile, protocol) # we create and process the output datafile
            if links:
                for v in val: # for each bubble in the chart, we create the bokeh plot corresponding to the value
                    generate_links(red, source, field, date, '{}-all-protocols'.format(v), outputdir, logofile, namefile, with_protocols)
    if at_least_one:
        # the complete scores with protocols together are processed and the result in written in another datafile
        general_filename = "{}_with-protocols_{}".format(namefile_data, namefile_date)
        res = process_file(general_score, general_filename, None)
        if links:
            for v in res: # for each bubble in the chart, we create the bokeh plot corresponding to the value
                generate_links(red, source, field, date, '{}-all-protocols'.format(v), outputdir, logofile, namefile, with_protocols)
else: # On the other case, we want to have the complete score for all the protocols together
    score={}
    exists = False
    if ck: # if combined keys are used anyway
        for prot in protocols: # we take the scores for each protocol
            protocol = prot.decode()
            keys = red.keys("{}:{}:{}*:{}".format(source,protocol,date,field))
            for k in sorted(keys): # For each day of the month
                redisKey = k.decode()
                exists = True
                process_score(red, redisKey, score, None, skip)
    else: # no combined keys
        keys = red.keys("{}:{}*:{}".format(source,date,field))
        for k in sorted(keys): # For each day of the month
            redisKey = k.decode()
            if red.exists(redisKey):
                exists = True
                process_score(red, redisKey, score, None, skip)
    if exists:
        namefile = "{}_{}".format(namefile_data, namefile_date)
        val = process_file(score, namefile, None)
        if links:
            for v in val: # for each bubble in the chart, we create the bokeh plot corresponding to the value
                generate_links(red, source, field, date, v, outputdir, logofile, namefile, with_protocols)

if gen: # Generate all the html files to display the charts, from the datafiles, following the template
    name_string = '##NAME##'
    logo_string = '##LOGO##'
    with open('{}/template.html'.format(potiron.current_path), 'r') as i:
        t = i.readlines()
    for file in os.listdir(outputdir):
        if file.endswith('.csv'):
            with open('{}{}.html'.format(outputdir, file[:-4]), 'w') as o:
                for l in t:
                    if name_string in l:
                        l = l.replace(name_string, file[:-4])
                    if logo_string in l:
                        l = l.replace(logo_string, logofile)
                    o.write(l)