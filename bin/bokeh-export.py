#!/usr/bin/env python3
import redis
import argparse
import sys
import os
import calendar
from bokeh.plotting import figure, output_file, show
from bokeh.models import HoverTool,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool,BasicTickFormatter
from bokeh.palettes import Category10_10 as palette

        
#defines the name of the output file
def output_name(source, field, fieldvalues, date, dest):
    value_str = ""
    for i in range(len(fieldvalues)):
        value_str = value_str + "_" + fieldvalues[i]
    return "{}{}_{}_{}{}".format(dest,source,date,field,value_str)
    

def process_graph(source, field, fieldvalues, date, dest):
    namefile=output_name(source,field,fieldvalues,date,dest)
    output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
    TOOLS = [HoverTool(tooltips=[("count","@y")]),PanTool(),BoxZoomTool(),WheelZoomTool(), SaveTool(), ResetTool()]
    p = figure(width=1500,height=750,tools=TOOLS)
    at_least_one = False
    days = calendar.monthrange(int(date[0:4]),int(date[4:6]))[1]
    for v in range(len(fieldvalues)):
        score=[]
        dayValue=[]
        exists = False
        for d in range(1,days+1):
            redisKey = "{}:{}{}:{}".format(source, date, format(d, '02d'), field)
            if red.exists(redisKey):
                countValue = red.zscore(redisKey, fieldvalues[v])
                score.append(countValue if countValue is not None else 0)
                dayValue.append(format(d, '02d'))
                exists = True
        if exists:
            color = palette[v%10]
            leg = "{}:{}".format(field, fieldvalues[v])
            p.line(dayValue,score,legend=leg,line_color=color,line_width=2)
            at_least_one = True
    if at_least_one:
        p.title.text = "Number of {} {} seen for each day on month {}, year {}".format(field, fieldvalues, date[4:6], date[0:4])
        p.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        show(p)
    else:
        print ("There is no such value for the {} you specified\n".format(field))

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('--source', type=str, nargs=1, help='Data source')
    parser.add_argument('--field', type=str, nargs=1, help='Field that should be displayed.')
    parser.add_argument('--values', nargs='+', help='Specific values of the field to display')
    parser.add_argument('--date', type=str, nargs=1, help='Date of the informations to display')
    parser.add_argument('--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('--dest', type=str, nargs=1, help='Destination path for the output file')
    args = parser.parse_args()
    
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    
    if args.unix is None:
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
        
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    
    members=""
    tab_members=[]
    for i in red.smembers('FIELDS'):
        val = i.decode()
        members = members + val + ", "
        tab_members.append(val)
    members=members[:-2]
    
    if args.field is None:
        sys.stderr.write('A field must be specified.\nChoose one of these : {}.\n'.format(members))
        sys.exit(1)
    if args.field[0] not in tab_members:
        sys.stderr.write('The field you chose does not exist.\nChoose one of these : {}.\n'.format(members))
        sys.exit(1)
    field = args.field[0]
        
    if args.date is None:
        sys.stderr.write('A date must be specified.\nThe format is : YYYYMM')
        sys.exit(1)
    date = args.date[0]
    
    if args.values is None:
        sys.stderr.write('At least one value must be specified\n')
        sys.exit(1)
    fieldvalues = args.values
    
    if args.dest is None:
        destpath = "./"
    else:
        if not os.path.exists(args.dest[0]):
            os.makedirs(args.dest[0])
        destpath = args.dest[0]
    
    process_graph(source, field, fieldvalues, date, destpath)