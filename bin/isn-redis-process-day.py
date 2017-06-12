#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import numpy as np
import argparse
import redis
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import BasicTickFormatter, HoverTool
from bokeh.layouts import column
import syslog


def errormsg(msg):
    syslog.openlog("isn-pcap", syslog.LOG_PID | syslog.LOG_PERROR,
                   syslog.LOG_INFO)
    syslog.syslog("[INFO] " + msg)
    

def string_timeline(h,s,e):
    h2 = h
    if e == '60':
        e = format(0, '02d')
        h2 = int(h)+1 if int(h)+1!=24 else e
        h2 = format(h2, '02d')
    sh = "{}:{}".format(h,s)
    eh = "{}:{}".format(h2,e)
    return sh, eh
    
    
if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Show ISN values")
    parser.add_argument("-d", "--date", type=str, nargs=1, help="Date of the files to process")
    parser.add_argument("-s", "--source", type=str, nargs=1, help="Honeypot data source")
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Destination path for the output file")
    parser.add_argument("-u", "--unix", type=str, nargs =1, help="Unix socket to connect to redis-server")
    parser.add_argument("-t", "--timeline", type=int, nargs=1, help="Timeline used to split data in graphs")
    args = parser.parse_args()

    if args.date is None:
        errormsg("A date should be defined")
        sys.exit(1)
    date = args.date[0]
    string_date = date.replace("-","")
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    if args.outputdir is None:
        output = "./out/"
    else:
        output = args.outputdir[0]
    if not os.path.exists(output):
        os.makedirs(output)
    if args.unix is None:
        sys.stderr.write('A unix socket must be specified\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    if args.timeline is None:
        timeline = 60
    else:
        timeline = args.timeline[0]
        if 60 % timeline != 0:
            sys.stderr.write('Please choose a number which devides 60 whithout any rest (1, 2, 3, 4, 5, 6, 10, 12, 15, 20, 30 or 60)\n')
            sys.exit(1)
    occurrence_num_hour = 60 / timeline
    TOOLS = "hover,crosshair,pan,wheel_zoom,zoom_in,zoom_out,box_zoom,undo,redo,reset,tap,save,box_select,poly_select,lasso_select,"
    for hours in range(0,24):
        h = format(hours, '02d')
        minutes = 0
        for nb in range(1,int(occurrence_num_hour+1)):
            w_input = []
            x_input = []
            y_input = []
            z_input = []
            start_min = format(minutes, '02d')
            while minutes < (timeline * nb):
                m = format(minutes, '02d')
                key = "{}_{}_{}:{}*".format(source,date,h,m)
                for line in red.keys(key):
                    line = line.decode()
                    y_input.append(red.hget(line,'tcpseq').decode())
                    w_input.append(red.hget(line,'tcpack').decode())
                    dport = red.hget(line,'dport').decode()
                    if dport == '':
                        dport = 0
                    z_input.append(int(dport))
                    x_input.append("{} {}".format(line.split("_")[1],line.split("_")[2]))
                minutes += 1
            end_min = format(minutes, '02d')
            x = np.array(x_input, dtype=np.datetime64)
            z = np.array(z_input)
            y = np.array(y_input)
            w = np.array(w_input)
            colors = [
                "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z*2, 30+z*2)
            ]
            start_hour, end_hour = string_timeline(h, start_min, end_min)
            title = " {} collected on {} between {} and {}".format(source, date, start_hour, end_hour)
            p_seq = figure(width=1500,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
            hoverseq = p_seq.select(dict(type=HoverTool))
            hoverseq.tooltips = [
                    ("index", "$index"),
                    ("timestamp", "@x{0,0}"),
                    ("number", "@y{0,0}")
                    ]
            p_seq.xaxis.axis_label = "Time"
            p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
            p_seq.scatter(x, y, color=colors, legend="seq values", alpha=0.5, )
            p_ack = figure(width=1500,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
            hoverack = p_ack.select(dict(type=HoverTool))
            hoverack.tooltips = [
                    ("index", "$index"),
                    ("timestamp", "@x{0,0}"),
                    ("number", "@y{0,0}")
                    ]
            p_ack.xaxis.axis_label = "Time"
            p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
            p_ack.scatter(x, w, color=colors, legend="ack values", alpha=0.5, )
            output_name = "color_scatter_{}_{}_{}-{}_syn+ack".format(source,date,start_hour,end_hour)
            output_dir = "{}{}/{}/{}/{}".format(output,date.split('-')[0],date.split('-')[1],date.split('-')[2],h)
            if not os.path.exists(output_dir):
                os.makedirs(output_dir)
            output_file("{}/{}.html".format(output_dir,output_name),
                        title="TCP ISN values in Honeypot", mode='inline')
            save(column(p_seq,p_ack))
            print("{} - {}".format(start_hour,end_hour))
            os.system("/usr/bin/phantomjs /usr/share/doc/phantomjs/examples/rasterize.js {0}/{1}.html {0}/{1}.png".format(output_dir,output_name))