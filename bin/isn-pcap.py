#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import numpy as np
import argparse
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import BasicTickFormatter, HoverTool
from bokeh.layouts import column
from bokeh.io import export_png
import syslog
import datetime


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
#        return "between {}:{} and {}:{}".format(hour[:2],hour[2:],
#                        (hour[:2] if (int(hour[2:])+10)<60 else (int(hour[:2])+1)%24),
#                        (format((int(hour[2:])+10)%60,'02d') if ((int(hour[:2])+1)%24)!=0 else "{} (the day after)".format(format((int(hour[2:])+10)%60,'02d'))))


# Process the ISN graphs directly from pcap files
def process_isn(src_dir,source,hour,outputdir,seq,ack):
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    w_input = []
    x_input = []
    y_input = []
    z_input = []
    braces = "{}"
    date = src_dir.split('/')[-4:-1]
    TOOLS="hover,crosshair,pan,wheel_zoom,zoom_in,zoom_out,box_zoom,undo,redo,reset,tap,save,box_select,poly_select,lasso_select,"
    # Command used to display an entire day of ISN values
    if hour is None:
        src_file = "{}{}".format(src_dir,braces)
        cmd = "ls {} | parallel --line-buffer --gnu tshark -n -q -Tfields -e frame.time_epoch -e tcp.seq -e tcp.ack \
        -e tcp.dstport -E separator=/s -o tcp.relative_sequence_numbers:FALSE -r {}".format(src_dir,src_file)
        width = 3600
        outputname = "color_scatter_{}_{}{}{}".format(source,date[0],date[1],date[2])
        title = " {} collected on {}/{}/{}".format(source, date[0],date[1],date[2])
    # Command used to display ISN values for the defined timeline
    else:
        filename = "{}-{}{}{}{}*".format(source,date[0],date[1],date[2],hour)
        cmd = "ls {}{} | parallel --line-buffer --gnu tshark -n -q -Tfields -e frame.time_epoch -e tcp.seq -e tcp.ack \
        -e tcp.dstport -E separator=/s -o tcp.relative_sequence_numbers:FALSE -r {}".format(src_dir,filename,braces)
        width = 1500
        outputname = "color_scatter_{}_{}{}{}_h{}".format(source,date[0],date[1],date[2],hour)
        title = " {} collected on {}/{}/{} {}".format(source,date[0],date[1],date[2],time_space(hour))

    proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    lines = proc.stdout.readlines()
    if not lines:
        print("There is no data available at the time you specified, please check the files and run the command again with a valid time value.")
        sys.exit(1)

    for line in lines:
        line = line[:-1].decode()
        timestamp, iseq, iack, dport = line.split(' ')
        a,_ = timestamp.split('.')
        dobj = datetime.datetime.fromtimestamp(float(a))
        stime = dobj.strftime("%Y-%m-%d %H:%M:%S")
        x_input.append(stime)
        y_input.append(iseq)
        w_input.append(iack)
        if dport == '':
            dport = 0
        z_input.append(int(dport))
    proc.wait()
    x = np.array(x_input,dtype=np.datetime64)
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
                ("timestamp", "@x"),
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
                ("timestamp", "@x"),
                ("number", "@y{0,0}")
                ]
        p_ack.xaxis.axis_label = "Time"
        p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p_ack.scatter(x, w, color=colors, legend="ack values", alpha=0.5, )
        p = p_ack
    output_file_name = "{}{}{}".format(outputdir,outputname,type_string)
#    output_file("{}{}{}.html".format(outputdir,outputname,type_string),
#            title="TCP ISN values in Honeypot", mode='inline')
    output_file("{}.html".format(output_file_name),
            title="TCP ISN values in Honeypot", mode='inline')
    if seq and ack:
        p = column(p_seq,p_ack)
    show(p)
    export_png(p, filename="{}.png".format(output_file_name))
    #os.system("/usr/bin/phantomjs /home/student/Downloads/phantomjs-2.1.1-linux-x86_64/examples/rasterize.js {0}.html {0}.png".format(output_file_name))

if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Show ISN values")
    parser.add_argument("-i", "--inputdir", type=str, nargs=1, help="Source directory for the files to process")
    parser.add_argument("-s", "--source", type=str, nargs=1, help="Sensor used as data source")
    parser.add_argument("-hr", "--hour", type=str, nargs=1, help="Hour of the informations wanted in the day selected")
    parser.add_argument("-t", "--type", type=str, nargs=1, help="Type of number : sequence or acknowledgement")
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Destination path for the output file")
    args = parser.parse_args()

    if args.inputdir is None:
        errormsg("A source directory should be defined")
        sys.exit(1)
    src_dir = args.inputdir[0]
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    if args.hour is None:
        print("ISNs for the complete day will be displayed.")
        hour = None
    else:
        hour = args.hour[0]
    if args.type is None:
        seq = True
        ack = True
    else:
        if args.type[0] == "seq":
            seq = True
            ack = False
        elif args.type[0] == "ack":
            seq = False
            ack = True
        else:
            print('Wrong value for this parameter. You can type "-t seq", "-t ack", \
            or simply not use any of these to display both sequence and acknowledgement numbers')
            sys.exit(1)
    if args.outputdir is None:
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
        if not outputdir.endswith('/'):
            outputdir = "{}/".format(outputdir)
    process_isn(src_dir,source,hour,outputdir,seq,ack)
