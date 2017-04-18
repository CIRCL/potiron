#!/usr/bin/env python3
import redis
import argparse
import sys
import os
from bokeh.plotting import figure, output_file, show, ColumnDataSource
from bokeh.models import HoverTool,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool

days = ["01","02","03","04","05","06","07","08","09","10",
        "11","12","13","14","15","16","17","18","19","20",
        "21","22","23","24","25","26","27","28","29","30","31"]

        
#defines the name of the output file
def output_name(field, fieldvalues, date, dest):
    value_str = ""
    for i in range(len(fieldvalues)):
        value_str = value_str + "_" + fieldvalues[i]
    return str(dest+"chp-5577-1:"+date+"_"+field+value_str)
    
    
def process_graph(field, fieldvalues, date, dest):
    namefile=output_name(field,fieldvalues,date,dest)
    output_file(namefile+".html", title=namefile.split("/")[-1])
    TOOLS = [HoverTool(tooltips=[("count","@count")]),PanTool(),BoxZoomTool(),WheelZoomTool(), SaveTool(), ResetTool()]
    p = figure(width=1500,height=750,tools=TOOLS)
    at_least_one = False
    for v in range(len(fieldvalues)):
        score=[]
        dayValue=[]
        exists = False
        for d in days:
            redisKey = "chp-5577-1:"+date+d+":"+field
            if red.exists(redisKey):
                countValue = red.zscore(redisKey, fieldvalues[v])
                score.append(countValue if countValue is not None else 0)
                dayValue.append(d)
                exists = True
        if exists:
            source = ColumnDataSource(data=dict(count=score,days=dayValue))
            p.circle('days','count',size=12,source=source)
            p.line(dayValue,score,legend=field)
            at_least_one = True
    if at_least_one:
        p.title.text = str("Numbers of " + field + " " + str(fieldvalues) + " seen for each day on month " + date[4:6] + ", year " + date[0:4])
        show(p)
    else:
        print ("There is no such value for the " + field + " you specified\n")

    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('--field', type=str, nargs=1, help='Field that should be displayed.')
    parser.add_argument('--values', nargs='+', help='Specific values of the field to display')
    parser.add_argument('--date', type=str, nargs=1, help='Date of the informations to display')
    parser.add_argument('--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('--dest', type=str, nargs=1, help='Destination path for the output file')
    args = parser.parse_args()
    
    if args.unix is None:
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
        
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    
    if args.field is None:
        sys.stderr.write('A field must be specified.\nChoose one of these : '+red.smembers('FIELDS')+'\n')
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
    
    process_graph(field, fieldvalues, date, destpath)