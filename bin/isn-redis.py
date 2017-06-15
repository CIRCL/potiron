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


# Display error message in case of error in the program execution
def errormsg(msg):
    syslog.openlog("isn-pcap", syslog.LOG_PID | syslog.LOG_PERROR,
                   syslog.LOG_INFO)
    syslog.syslog("[INFO] " + msg)
    

# Define the part of the legend which contains the hours scale
def time_space(hour):
    if len(hour) == 2:
        return "between {} and {}".format(hour,format((int(hour)+1)%24,'02d'))
    elif len(hour) == 4:
        return "between {}:{} and {}:{}".format(hour[:2],hour[2:],
                        (hour[:2] if (int(hour[2:])+5)<60 else (int(hour[:2])+1)%24),
                        (format((int(hour[2:])+5)%60,'02d') if ((int(hour[:2])+1)%24)!=0 else "{} (the day after)".format(format((int(hour[2:])+5)%60,'02d'))))
    elif len(hour) == 3:
        print("Please choose a --hour parameter between 'HH' to display a complete hour or 'HHmm' to show only 5 minutes")
        sys.exit(1)    


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Show ISN values")
    parser.add_argument("-d", "--date", type=str, nargs=1, help="Date of the files to process")
    parser.add_argument("-s", "--source", type=str, nargs=1, help="Honeypot data source")
    parser.add_argument("--hour", type=str, nargs=1, help="Hour of the informations wanted in the day selected")
    parser.add_argument("-t", "--type", type=str, nargs=1, help="Type of number : sequence or acknowledgement")
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Destination path for the output file")
    parser.add_argument("-u", "--unix", type=str, nargs =1, help="Unix socket to connect to redis-server")
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
    # If no timeline is defined, options of graphs for the whole day
    if args.hour is None:
        hour = None
        print("ISNs for the complete day will be displayed.")
        width = 3600
        outputname = "color_scatter_{}_{}".format(source,date)
        title = " {} collected on {}/{}/{}".format(source,string_date[0:4],string_date[4:6],string_date[6:8])
    # Options of graphs for the defined timeline
    else:
        hour = args.hour[0]
        width = 1500
        outputname = "color_scatter_{}_{}_h{}".format(source,date,hour)
        title = " {} collected on {}/{}/{} {}".format(source,string_date[0:4],string_date[4:6],string_date[6:8],time_space(hour))
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
    
    w_input = []
    x_input = []
    y_input = []
    z_input = []
    TOOLS="hover,crosshair,pan,wheel_zoom,zoom_in,zoom_out,box_zoom,undo,redo,reset,tap,save,box_select,poly_select,lasso_select,"
    key = "{}_{}_{}*".format(source,date,hour)
    for line in red.keys(key):
        line = line.decode()
        y_input.append(red.hget(line,'tcpseq').decode())
        w_input.append(red.hget(line,'tcpack').decode())
        dport = red.hget(line,'dport').decode()
        if dport == '':
            dport = 0
        z_input.append(int(dport))
        x_input.append("{} {}".format(line.split("_")[1],line.split("_")[2]))
    x = np.array(x_input, dtype=np.datetime64)
    z = np.array(z_input)
    colors = [
        "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z*2, 30+z*2)
    ]
    type_string = ""
    # Definition of the sequence numbers plot
    if seq:
        type_string+="_seq"
        y = np.array(y_input)
        p_seq = figure(width=width,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
        hoverseq = p_seq.select(dict(type=HoverTool))
        hoverseq.tooltips = [
                ("index", "$index"),
                ("timestamp", "@x{0,0}"),
                ("number", "@y{0,0}")
                ]
        p_seq.xaxis.axis_label = "Time"
        p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p_seq.scatter(x, y, color=colors, legend="seq values", alpha=0.5, )
        p = p_seq
    # Definition of the acknowledgement numbers plot
    if ack:
        type_string+="_ack"
        w = np.array(w_input)
        p_ack = figure(width=width,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
        hoverack = p_ack.select(dict(type=HoverTool))
        hoverack.tooltips = [
                ("index", "$index"),
                ("timestamp", "@x{0,0}"),
                ("number", "@y{0,0}")
                ]
        p_ack.xaxis.axis_label = "Time"
        p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p_ack.scatter(x, w, color=colors, legend="ack values", alpha=0.5, )
        p = p_ack
    output_file_name = "{}{}{}".format(output,outputname,type_string)
    output_file("{}.html".format(output_file_name),
            title="TCP ISN values in Honeypot", mode='inline')
    # Draw two plots
    if seq and ack:
        save(column(p_seq,p_ack))
    # Draw the selected plot
    else:
        save(p)
    # Export the plot as .png
    os.system("/usr/bin/phantomjs /usr/share/doc/phantomjs/examples/rasterize.js {0}.html {0}.png".format(output_file_name))