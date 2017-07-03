#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import os
import numpy as np
import argparse
import redis
import datetime
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import BasicTickFormatter, HoverTool
from bokeh.layouts import column
from bokeh.io import export_png
from bokeh.palettes import Category20_20 as palette
import syslog


# Display error message in case of error in the program execution
def errormsg(msg):
    syslog.openlog("isn-pcap", syslog.LOG_PID | syslog.LOG_PERROR,
                   syslog.LOG_INFO)
    syslog.syslog("[INFO] " + msg)
    
    
# Define value of hour and minutes from an hour in format HH:mm
def define_hour(hour):
    if len(hour) != 5:
        hrs = hour.split(':')
        if len(hrs) == 1:
            m = '00'
        h = format(hrs[0], '02d')
    else:
        h,m = hour.split(':')
    return h,m


# Define the part of the legend which contains the hours scale
def time_space(timeline,date,h,m,string):
    t = 0
    edate = date
    eh = h
    em = m
    while t < timeline:
        t,edate,eh,em = update_time(t,edate,eh,em)
    if string:
        if edate == date:
            return "on {} between {}:{} and {}:{}".format(date,h,m,eh,em)
        else:
            return "between {} {}:{} and {} {}:{}".format(date,h,m,edate,eh,em)
    else:
        if edate == date:
            return "{}_{}:{}-{}:{}".format(date,h,m,eh,em)
        else:
            return "{}_{}:{}-{}_{}:{}".format(date,h,m,edate,eh,em)


# Update value of time
def update_time(t,date,h,m):
    t += 1
    mn = (int(m) + 1) % 60
    if mn == 0:
        hrs = (int(h) + 1) % 60
        if hrs == 0:
            yr,mth,d = date.split('-')
            date = (datetime.date(int(yr),int(mth),int(d)) + datetime.timedelta(1)).strftime('%Y-%m-%d')
        h = format(hrs, '02d')
    m = format(mn, '02d')
    return t,date,h,m


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Show ISN values")
    parser.add_argument("-d", "--date", type=str, nargs=1, help="Date of the files to process")
    parser.add_argument("-s", "--source", type=str, nargs=1, help="Honeypot data source")
    parser.add_argument("-hr", "--hour", type=str, nargs=1, help="Hour of the informations wanted in the day selected")
    parser.add_argument("-tl", "--timeline", type=int, nargs=1, help="Timeline of the data to display")
    parser.add_argument("-t", "--type", type=str, nargs=1, help="Type of number : sequence or acknowledgement")
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Destination path for the output file")
    parser.add_argument("-u", "--unix", type=str, nargs =1, help="Unix socket to connect to redis-server")
    parser.add_argument("-pf", "--port_filter", nargs='+', help="Filter some ports to display")
    args = parser.parse_args()
    braces = "{}"
    if args.date is None:
        errormsg("A date should be defined")
        sys.exit(1)
    date = args.date[0]
    string_date = date.replace("-","")
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    # If no timeline is defined, error
    if args.hour is None:
        errormsg('You should define an hour for your timeline with the parameter: --hour\n')
        sys.exit(1)
    # Options of graphs for the defined timeline
    else:
        hour = args.hour[0]
        width = 1500
        h,m = define_hour(hour)
        # timeline
        if args.timeline is None:
            timeline = 5
        else:
            timeline = args.timeline[0]
        outputname = "color_scatter_{}_{}".format(source,time_space(timeline,date,h,m,False))
        title = " {} collected {}".format(source,time_space(timeline,date,h,m,True))
    # If no type of plot to process is given, simply process both two types (seq & ack)
    if args.type is None:
        seq = True
        ack = True
    # On the other case, obviously only the specified type of plot will be processed
    else:
        if args.type[0] == "seq":
            seq = True
            ack = False
        elif args.type[0] == "ack":
            seq = False
            ack = True
        else:
            errormsg('Wrong value for this parameter. You can type "-t seq", "-t ack", \
            or simply not use any of these to display both sequence and acknowledgement numbers')
            sys.exit(1)
    if args.outputdir is None:
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
        if not outputdir.endswith('/'):
            outputdir = "{}/".format(outputdir)
    if not os.path.exists(outputdir):
            os.makedirs(outputdir)
    if args.unix is None:
        sys.stderr.write('A unix socket must be specified\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)

    TOOLS="hover,crosshair,pan,wheel_zoom,zoom_in,zoom_out,box_zoom,undo,redo,reset,tap,save,box_select,poly_select,lasso_select,"
    if args.port_filter is None:
        key = "{}*".format(source)
        w_input = []
        x_input = []
        y_input = []
        zseq_input = []
        zack_input = []
        t = 0
        while t < timeline:
            redisKey = "{}{}_{}:{}*".format(key,date,h,m)
            for line in red.keys(redisKey):
                line = line.decode()
                y_input.append(red.hget(line,'tcpseq').decode())
                w_input.append(red.hget(line,'tcpack').decode())
                sport = line.split('_')[1][3:]
                dport = line.split('_')[2][3:]
                if sport == '':
                    sport = 0
                if dport == '':
                    dport = 0
                zseq_input.append(int(dport))
                zack_input.append(int(sport))
                x_input.append("{} {}".format(line.split("_")[3],line.split("_")[4]))
            t,date,h,m = update_time(t,date,h,m)
        x = np.array(x_input, dtype=np.datetime64)
        type_string = ""
        # Definition of the sequence numbers plot
        if seq:
            type_string+="_seq"
            y = np.array(y_input)
            z_seq = np.array(zseq_input)
            colorseq = [
                "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z_seq*2, 30+z_seq*2)
            ]
            p_seq = figure(width=width,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
            hoverseq = p_seq.select(dict(type=HoverTool))
            hoverseq.tooltips = [
                    ("index", "$index"),
                    ("timestamp", "@x{0,0}"),
                    ("number", "@y{0,0}"),
                    ]
            p_seq.xaxis.axis_label = "Time"
            p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
            p_seq.scatter(x, y, color=colorseq, legend="seq values", alpha=0.5, )
            p = p_seq
        # Definition of the acknowledgement numbers plot
        if ack:
            type_string+="_ack"
            w = np.array(w_input)
            z_ack = np.array(zack_input)
            colorsack = [
                "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z_ack*2, 30+z_ack*2)
            ]
            p_ack = figure(width=width,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
            hoverack = p_ack.select(dict(type=HoverTool))
            hoverack.tooltips = [
                    ("index", "$index"),
                    ("timestamp", "@x{0,0}"),
                    ("number", "@y{0,0}"),
                    ]
            p_ack.xaxis.axis_label = "Time"
            p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
            p_ack.scatter(x, w, color=colorsack, legend="ack values", alpha=0.5, )
            p = p_ack
    else:
        type_string = ""
        if seq:
            type_string+="_seq"
            p_seq = figure(width=width,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
            hoverseq = p_seq.select(dict(type=HoverTool))
            hoverseq.tooltips = [
                    ("index", "$index"),
                    ("timestamp", "@x{0,0}"),
                    ("number", "@y{0,0}"),
                    ]
            p_seq.xaxis.axis_label = "Time"
            p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        if ack:
            type_string+="_ack"
            p_ack = figure(width=width,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
            hoverack = p_ack.select(dict(type=HoverTool))
            hoverack.tooltips = [
                    ("index", "$index"),
                    ("timestamp", "@x{0,0}"),
                    ("number", "@y{0,0}"),
                    ]
            p_ack.xaxis.axis_label = "Time"
            p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        ports = args.port_filter
        port_color = np.array(ports)
        type_string+="_port"
        if len(ports) > 1:
            type_string+="s"
        for port in ports:
            w_input = []
            x_input = []
            y_input = []
            key = "{}*dst{}".format(source,port)
            t = 0
            h,m = define_hour(hour)
            while t < timeline:
                redisKey = "{}_{}_{}:{}*".format(key,date,h,m)
                for line in red.keys(redisKey):
                    line = line.decode()
                    x_input.append("{} {}".format(line.split("_")[3],line.split("_")[4]))
                    y_input.append(red.hget(line,'tcpseq').decode())
                    w_input.append(red.hget(line,'tcpack').decode())
                t,date,h,m = update_time(t,date,h,m)
            x = np.array(x_input, dtype=np.datetime64)
            color = palette[ports.index(port)%20]
            if seq:
                y = np.array(y_input)
                p_seq.scatter(x, y, color=color, legend="seq values - port {}".format(port), alpha=0.5)

            if ack:
                w = np.array(w_input)
                p_ack.scatter(x, w, color=color, legend="ack values - port {}".format(port), alpha=0.5)
            type_string+="_{}".format(port)
        if seq:
            p_seq.legend.click_policy = "hide"
            p = p_seq
        if ack:
            p_ack.legend.click_policy = "hide"
            p = p_ack
    output_file_name = "{}{}{}".format(outputdir,outputname,type_string)
    output_file("{}.html".format(output_file_name),
            title="TCP ISN values in Honeypot", mode='inline')
    # In case of two plots
    if seq and ack:
        p = column(p_seq,p_ack)
    # Draw the plot(s)
    save(p)
    # Export the plot as .png
    export_png(p, filename="{}.png".format(output_file_name))
#    os.system("/usr/bin/phantomjs /usr/share/doc/phantomjs/examples/rasterize.js {0}.html {0}.png".format(output_file_name))
