#!/usr/bin/env python3

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
def output_name(source, field, dest, yearmonth, day):
    data_part = "{}{}_{}".format(dest,source,field)
    date_part = "{}-{}-{}".format(yearmonth[0:4],yearmonth[4:6],day)
    return data_part, date_part


# Store in a disctionary of scores the scores of each value tu display, for all the protocols (in case of combined keys)
def process_score(red, redisKey, score, skip):
    for v in red.zrevrangebyscore(redisKey,MAXVAL,0):
        countValue = red.zscore(redisKey,v)
        val = v.decode()
        if val in skip:
            continue
        if val in score:
            score[val] += countValue
        else:
            score[val] = countValue
         
            
# Search the scores in the ranged list of values, and write them in the output .csv file
def process_file(red, redisKey, name, field, protocol, field_string, skip, limit):
    l = 0
    values = []
    # For each value ranged in decreasing order
    for v in red.zrevrangebyscore(redisKey,MAXVAL,0):
        val = v.decode()
        # If the current value is not one that should be skipped, increment the number of values to include in the chart
        if val not in skip :
            values.append(val)
            l += 1
        # When the limit value is reached, we don't need to increment anymore, we break the loop
        if l >= limit:
            break
    # Write all the values and their scores into the csv datafile
    with open("{}.csv".format(name),'w') as f:
        f.write("id,value\n")
        for v in values:
            val = bubble_annotation(field,field_string,v,potiron.potiron_path,protocol)
            f.write("{}{},\n".format(v,val))
            f.write("{}{},{}\n".format(v,val,red.zscore(redisKey,v)))
    return values
    
            
# Sort the scores after the values for all protocols has been counted (in case of comined keys),
# and write the top values in the output datafile
def process_general_file(score, namefile, field, field_string, skip, limit):
    res = list(sorted(score, key=score.__getitem__, reverse=True))
    l = 0
    values = []
    for s in res:
        if s not in skip:
            values.append(s)
            l+=1
        if l >= limit:
            break
    with open("{}.csv".format(namefile), 'w') as f:
        f.write("id,value\n")
        for v in values :
            val = bubble_annotation(field,field_string,v,potiron.potiron_path,None)
            f.write("{}{},\n".format(v,val))
            f.write("{}{},{}\n".format(v,val,int(score[v])))
    return values


def generate_links(red, source, field, date, v, outputdir, logofile, namefile, lentwo):
    n = namefile.split('/')
    name = n[-1].split('_')
    bokeh_filename = ''
    for s in n[:-1]:
        bokeh_filename += '{}/'.format(s)
    if lentwo:
        bokeh_filename += '{}_{}_{}_with-protocols_{}.html'.format(name[0],name[3][:-3],name[1],v.split('-')[0])
    else:
        bokeh_filename += '{}_{}_{}_{}.html'.format(name[0],name[2][:-3],name[1],v)
    if not os.path.exists(bokeh_filename):
        bokeh_month.process_file(red, source, field, date, [v], outputdir, logofile, False)


def process_all_files(red, source, date, field, limit, skip, outputdir, links, gen, logofile, ck, lentwo):
    current_path = potiron.current_path
    potiron_path = potiron.potiron_path
    # Definition of the protocol values
    protocols_path = "{}doc/protocols".format(potiron_path)
    protocols = potiron.define_protocols(protocols_path)
    # Definition of the strings containing the informations of the field, used in the legend and the file name
    field_string, field_in_file_name = field2string(field, potiron_path)
    
    days = calendar.monthrange(int(date[0:4]),int(date[4:6]))[1]
    # For each day of the month
    for d in range(1,days+1):
        namefile_data, namefile_date = output_name(source,field_in_file_name,outputdir,date,format(d, '02d'))
        day = format(d, '02d')
        if lentwo:
            score = {}
            for prot in protocols:
                protocol = protocols[prot]
                redisKey = "{}:{}:{}{}:{}".format(source,protocol,date,day,field)
                namefile = "{}_{}_{}".format(namefile_data, protocol,namefile_date)
                if red.exists(redisKey):
                    val = process_file(red, redisKey, namefile, field, protocol, field_string, skip, limit)
                    process_score(red, redisKey, score, skip)
                    if links:
                        for v in val:
                            generate_links(red, source, field, date, '{}-all-protocols'.format(v), outputdir, logofile, namefile, lentwo)
            general_namefile = "{}_with-protocols_{}".format(namefile_data, namefile_date)
            res = process_general_file(score, general_namefile, field, field_string, skip, limit)
            if links:
                for v in res:
                    generate_links(red, source, field, date, '{}-all-protocols'.format(v), outputdir, logofile, namefile, lentwo)
        else:
            if ck:
                score = {}
                for prot in protocols:
                    protocol = protocols[prot]
                    redisKey = "{}:{}:{}{}:{}".format(source,protocol,date,day,field)
                    if red.exists(redisKey):
                        process_score(red, redisKey, score, skip)
                general_namefile = "{}_{}".format(namefile_data, namefile_date)
                res = process_general_file(score, general_namefile, field, field_string, skip, limit)
                if links:
                    for v in res:
                        generate_links(red, source, field, date, v, outputdir, logofile, general_namefile, lentwo)
            else:
                redisKey = "{}:{}{}:{}".format(source, date, day, field)
                namefile = "{}_{}".format(namefile_data, namefile_date)
                if red.exists(redisKey):
                    val = process_file(red, redisKey, namefile, field, None, field_string, skip, limit)
                    if links:
                        for v in val:
                            generate_links(red, source, field, date, v, outputdir, logofile, namefile, lentwo)
    
    if gen:
        name_string = '##NAME##'
        logo_string = '##LOGO##'
        with open('{}/template.html'.format(current_path), 'r') as i:
            t = i.readlines()
        for file in os.listdir(outputdir):
            if file.endswith('.csv'):
                with open('{}{}.html'.format(outputdir,file[:-4]), 'w') as o:
                    for l in t:
                        if name_string in l:
                            l = l.replace(name_string, file[:-4])
                        if logo_string in l:
                            l = l.replace(logo_string, logofile)
                        o.write(l)


if __name__ == '__main__':
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
    
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    
    if args.date is None:
        sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
        sys.exit(1)
    date = args.date[0].replace("-","")
    
    if args.field is None:
        sys.stderr.write('A field must be specified.\n')
        sys.exit(1)
    field = args.field[0]
    
    if args.limit is None:
        limit = 10
    else:
        limit = args.limit[0]
    
    if args.skip is None:
        args.skip = []
    
    if args.outputdir is None:
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
        if not outputdir.endswith('/'):
            outputdir = "{}/".format(outputdir)
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    
    if args.unix is None:
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    
    lentwo = args.without_protocols
    if red.sismember("CK", "YES"):
        ck = True
    else:
        if lentwo:
            without_protocols = False
            potiron.infomsg('You did not choose to use the parameter "without_protocols" but your redis database is not currently supporting combined keys.\
                            It will continue anyway without specifying each protocol.')
        ck = False
    
    links = args.links
    
    gen = args.generate
    
    # Define path of circl logo, based on potiron path
    if args.logo is None:
        logofile = "{}doc/circl.png".format(potiron.potiron_path)
    else:
        logofile = args.logo[0]
    process_all_files(red, source, date, field, limit, args.skip, outputdir, links, gen, logofile, ck, lentwo)
