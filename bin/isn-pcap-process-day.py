#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import subprocess
import sys
import os
import numpy as np
import argparse
from bokeh.plotting import figure, save, output_file
from bokeh.models import BasicTickFormatter, HoverTool
from bokeh.layouts import column
import syslog
import datetime


def errormsg(msg):
    syslog.openlog("isn-pcap", syslog.LOG_PID | syslog.LOG_PERROR,
                   syslog.LOG_INFO)
    syslog.syslog("[INFO] " + msg)


def process_isn(src_dir,source,output):
    braces = "{}"
    date = src_dir.split('/')[-4:-1]
    print(date)
    tshark = "parallel --gnu --line-buffer tshark -n -q -Tfields -e frame.time_epoch -e tcp.seq \
    -e tcp.ack -e tcp.dstport -E separator=/s -o tcp.relative_sequence_numbers:FALSE -r {}".format(braces)
    TOOLS = "hover,crosshair,pan,wheel_zoom,zoom_in,zoom_out,box_zoom,undo,redo,reset,tap,save,box_select,poly_select,lasso_select,"
    for hours in range(0,24):
        h = format(hours, '02d')
        w_input = []
        x_input = []
        y_input = []
        z_input = []
        cmd = "find {} -type f -print | sort | grep {}-{}{}{}{} | {}".format(src_dir,source,date[0],date[1],date[2],h,tshark)
        proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        lines = proc.stdout.readlines()
        if not lines:
            continue
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
        y = np.array(y_input)
        w = np.array(w_input)
        colors = [
            "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z*2, 30+z*2)
        ]
        title = " {} collected on {}/{}/{}".format(source, date[0],date[1],date[2])
        p_seq = figure(width=1500, height=700, tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
        p_seq.xaxis.axis_label = "Time"
        p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p_seq.scatter(x, y, color=colors, legend="seq values", alpha=0.5, )
        hoverseq = p_seq.select(dict(type=HoverTool))
        hoverseq.tooltips = [
                ("index", "$index"),
                ("timestamp", "@x"),
                ("number", "@y{0,0}")
                ]
        p_ack = figure(width=1500, height=700, tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
        p_ack.xaxis.axis_label = "Time"
        p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p_ack.scatter(x, w, color=colors, legend="ack values", alpha=0.5, )
        hoverack = p_ack.select(dict(type=HoverTool))
        hoverack.tooltips = [
                ("index", "$index"),
                ("timestamp", "@x"),
                ("number", "@y{0,0}")
                ]
        output_name = "color_scatter_{}_{}{}{}_{}_syn+ack".format(source,date[0],date[1],date[2],h)
        output_dir = "{}{}/{}/{}/{}".format(output,date[0],date[1],date[2],h)
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)
        output_file("{}/{}.html".format(output_dir,output_name),
                    title="TCP ISN values in Honeypot", mode='inline')
        save(column(p_seq,p_ack))
        print(h)
        os.system("/usr/bin/phantomjs /usr/share/doc/phantomjs/examples/rasterize.js {0}/{1}.html {0}/{1}.png".format(output_dir,output_name))


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description="Show ISN values")
    parser.add_argument("-i", "--input", type=str, nargs=1, help="Source directory for the files to process")
    parser.add_argument("-s", "--source", type=str, nargs=1, help="Honeypot data source")
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Destination path for the output file")
    args = parser.parse_args()

    if args.input is None:
        errormsg("A source directory should be defined")
        sys.exit(1)
    src_dir = args.input[0]
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
    process_isn(src_dir,source,output)
