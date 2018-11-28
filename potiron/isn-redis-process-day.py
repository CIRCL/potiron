#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2017 Christian Studer
#    Copyright (C) 2017 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

import sys
import os
import numpy as np
import argparse
import redis
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import BasicTickFormatter, HoverTool, ColumnDataSource
from bokeh.layouts import column
from bokeh.io import export_png
from bokeh.palettes import Category20_20 as palette
import syslog


# Display error message in case of error in the program execution
def errormsg(msg):
    syslog.openlog("isn-pcap", syslog.LOG_PID | syslog.LOG_PERROR,
                   syslog.LOG_INFO)
    syslog.syslog("[INFO] " + msg)


# Definition of the timeline part of the legend and title of the plot
def string_timeline(h,s,e):
    h2 = h
    if e == '60':
        e = format(0, '02d')
        h2 = int(h)+1 if int(h)+1!=24 else 0
        h2 = format(h2, '02d')
    sh = "{}:{}".format(h,s)
    eh = "{}:{}".format(h2,e)
    return sh, eh


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description="Show ISN values")
    parser.add_argument("-d", "--date", type=str, nargs=1, help="Date of the files to process (with the format YYYY-MM-DD)")
    parser.add_argument("-hr", "--hour", type=str, nargs=1, help="Hour of the informations wanted in the day selected (with the format HH:mm or HH")
    parser.add_argument("-s", "--source", type=str, nargs=1, help='Sensor used as data source (ex: "chp-5890-1")')
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Destination path for the output file")
    parser.add_argument("-u", "--unix", type=str, nargs =1, help="Unix socket to connect to redis-server")
    parser.add_argument("-tl", "--timeline", type=int, nargs=1, help="Timeline used to split data in graphs (in minutes)")
    parser.add_argument("-pf", "--port_filter", nargs='+', help='Filter the ports you want to display (ex: "22 23 80")')
    parser.add_argument("-e", "--export", action="store_true", help="Choose to export plot(s) in png to have an overview before opening it")
    args = parser.parse_args()

    if args.date is None:
        errormsg("A date should be defined")
        sys.exit(1)
    date = args.date[0]
    string_date = date.replace("-","")
    if len(date.split('-')) == 1:
        date = "{}-{}-{}".format(date[0:4],date[4:6],date[6:8])
    if args.hour is None:
        sh = 0
        eh = 24
    else:
        hh = args.hour[0].split(':')
        sh = int(hh[0])
        eh = sh + 1
        if len(hh) > 1:
            eh = int(hh[1])
            if eh > 24 or eh < sh:
                eh = 24
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
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
    if args.timeline is None:
        timeline = 60
    else:
        timeline = args.timeline[0]
        if 60 % timeline != 0:
            sys.stderr.write('Please choose a number which devides 60 whithout any rest.\n')
            sys.exit(1)
    export = args.export
    # Number of occurrences per hour with the defined timeline
    occurrence_num_hour = 60 / timeline
    TOOLS = "hover,crosshair,pan,wheel_zoom,zoom_in,zoom_out,box_zoom,undo,redo,reset,tap,save,box_select,poly_select,lasso_select,"
    # For each hour of the day
    for hours in range(sh,eh):
        h = format(hours, '02d')
        # if no port filter is defined
        if args.port_filter is None:
            key = "{}*{}_{}".format(source,date,h)
            # If there is no key corresponding to a precise hour, go directly is the next hour
            if len(red.keys("{}*".format(key))) == 0:
                continue
            minutes = 0
            # For each period of time corresponding to the timeline
            for nb in range(1,int(occurrence_num_hour+1)):
                w_input = []
                x_input = []
                y_input = []
                zd_input = []
                zs_input = []
                start_min = format(minutes, '02d')
                # For each minute in the timeline
                while minutes < (timeline * nb):
                    m = format(minutes, '02d')
                    keys = "{}:{}*".format(key,m)
                    for line in red.keys(keys):
                        line = line.decode()
                        y_input.append(red.hget(line,'tcpseq').decode())
                        w_input.append(red.hget(line,'tcpack').decode())
                        sport = line.split('_')[1][3:]
                        dport = line.split('_')[2][3:]
                        if sport == '':
                            sport = 0
                        if dport == '':
                            dport = 0
                        zd_input.append(int(dport))
                        zs_input.append(int(sport))
                        x_input.append("{} {}".format(line.split("_")[3],line.split("_")[4]))
                    minutes += 1
                end_min = format(minutes, '02d')
                # If there is at least one occurrence found in the current timeline, draw the plot
                if len(x_input) > 0:
                    x = np.array(x_input, dtype=np.datetime64)
                    z_d = np.array(zd_input)
                    z_s = np.array(zs_input)
                    y = np.array(y_input)
                    w = np.array(w_input)
                    colorseq = [
                        "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z_d*2, 30+z_d*2)
                    ]
                    colorsack = [
                        "#%02x%02x%02x" % (int(r), int(g), 150) for r, g in zip(50+z_s*2, 30+z_s*2)
                    ]
                    start_hour, end_hour = string_timeline(h, start_min, end_min)
                    title = " {} collected on {} between {} and {}".format(source, date, start_hour, end_hour)
                    # Definition of the sequence numbers plot
                    p_seq = figure(width=1500,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
                    hoverseq = p_seq.select(dict(type=HoverTool))
                    hoverseq.tooltips = [
                            ("index", "$index"),
                            ("timestamp", "@x{%F %H:%M:%S}"),
                            ("number", "@y{0,0}"),
                            ("dest port", "@dport"),
                            ("src port", "@sport")
                            ]
                    hoverseq.formatters = {
                            'x': 'datetime'}
                    seq_sourceplot = ColumnDataSource(data=dict(
                            x = x,
                            y = y,
                            dport = z_d,
                            sport = z_s,
                            colorseq = colorseq
                            ))
                    p_seq.xaxis.axis_label = "Time"
                    p_seq.yaxis.axis_label = "Sequence Numbers"
                    p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
                    p_seq.scatter(x='x', y='y', color='colorseq', legend="seq values", alpha=0.5, source=seq_sourceplot)
                    p_ack = figure(width=1500,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
                    hoverack = p_ack.select(dict(type=HoverTool))
                    hoverack.tooltips = [
                            ("index", "$index"),
                            ("timestamp", "@x{%F %H:%M:%S}"),
                            ("number", "@y{0,0}"),
                            ("dest port", "@dport"),
                            ("src port", "@sport")
                            ]
                    hoverack.formatters = {
                            'x': 'datetime'}
                    ack_sourceplot = ColumnDataSource(data=dict(
                            x = x,
                            w = w,
                            dport = z_d,
                            sport = z_s,
                            colorsack = colorsack
                            ))
                    p_ack.xaxis.axis_label = "Time"
                    p_ack.yaxis.axis_label = "Acknowledgement Numbers"
                    p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
                    p_ack.scatter(x='x', y='w', color='colorsack', legend="ack values", alpha=0.5, source=ack_sourceplot)
                    output_name = "color_scatter_{}_{}_{}-{}_syn+ack".format(source,date,start_hour,end_hour)
                    output_dir = "{}{}/{}/{}/{}".format(outputdir,date.split('-')[0],date.split('-')[1],date.split('-')[2],h)
                    if not os.path.exists(output_dir):
                        os.makedirs(output_dir)
                    output_file("{}/{}.html".format(output_dir,output_name),
                                title="TCP ISN values in Honeypot", mode='inline')
                    # Write the html file and save it
                    p = column(p_seq,p_ack)
                    save(p)
                    print("{} - {}".format(start_hour,end_hour))
                    # Export the plot into a png file
                    if export:
                        export_png(p, filename = "{}/{}.png".format(output_dir,output_name))
        else:
            ports = args.port_filter
            minutes = 0
            # For each period of time corresponding to the timeline
            for nb in range(1,int(occurrence_num_hour+1)):
                start_min = format(minutes, '02d')
                it_minutes = minutes
                start_hour, end_hour = string_timeline(h, start_min, format((minutes+timeline),'02d'))
                title = " {} collected on {} between {} and {}".format(source, date, start_hour, end_hour)
                # Definition of the sequence numbers plot
                p_seq = figure(width=1500,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP sequence values in Honeypot {}".format(title))
                hoverseq = p_seq.select(dict(type=HoverTool))
                hoverseq.tooltips = [
                        ("index", "$index"),
                        ("timestamp", "@x{%F %H:%M:%S}"),
                        ("number", "@y{0,0}")
                        ]
                hoverseq.formatters = {
                        'x': 'datetime'}
                p_seq.xaxis.axis_label = "Time"
                p_seq.yaxis.axis_label = "Sequence Numbers"
                p_seq.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
                # Definition of the aclnowledgement numbers plot
                p_ack = figure(width=1500,height=700,tools=TOOLS, x_axis_type="datetime", title="TCP acknowledgement values in Honeypot {}".format(title))
                hoverack = p_ack.select(dict(type=HoverTool))
                hoverack.tooltips = [
                        ("index", "$index"),
                        ("timestamp", "@x{%F %H:%M:%S}"),
                        ("number", "@y{0,0}")
                        ]
                hoverack.formatters = {
                        'x': 'datetime'}
                p_ack.xaxis.axis_label = "Time"
                p_ack.yaxis.axis_label = "Acknowledgement Numbers"
                p_ack.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
                ports_string = "port"
                if len(ports) > 1:
                    ports_string+="s"
                for port in ports:
                    minutes = it_minutes
                    key = "{}*dst{}_{}_{}".format(source,port,date,h)
                    # If there is no key corresponding to a precise hour, go directly is the next hour
                    if len(red.keys("{}*".format(key))) == 0:
                        continue
                    w_input = []
                    x_input = []
                    y_input = []
                    # For each minute in the timeline
                    while minutes < (timeline * nb):
                        m = format(minutes, '02d')
                        keys = "{}:{}*".format(key,m)
                        for line in red.keys(keys):
                            line = line.decode()
                            y_input.append(red.hget(line,'tcpseq').decode())
                            w_input.append(red.hget(line,'tcpack').decode())
                            x_input.append("{} {}".format(line.split("_")[3],line.split("_")[4]))
                        minutes += 1
                    x = np.array(x_input, dtype=np.datetime64)
                    y = np.array(y_input)
                    w = np.array(w_input)
                    color = palette[ports.index(port)%20]
                    p_seq.scatter(x, y, color=color, legend="seq values - port {}".format(port), alpha=0.5)
                    p_ack.scatter(x, w, color=color, legend="ack values - port {}".format(port), alpha=0.5)
                    ports_string += "_{}".format(port)
                p_seq.legend.click_policy = "hide"
                p_ack.legend.click_policy = "hide"
                output_name = "color_scatter_{}_{}_{}-{}_{}_syn+ack".format(source,date,start_hour,end_hour,ports_string)
                output_dir = "{}{}/{}/{}/{}".format(outputdir,date.split('-')[0],date.split('-')[1],date.split('-')[2],h)
                if not os.path.exists(output_dir):
                    os.makedirs(output_dir)
                output_file("{}/{}.html".format(output_dir,output_name),
                            title="TCP ISN values in Honeypot", mode='inline')
                # Write the html file and save it
                p = column(p_seq,p_ack)
                save(p)
                print("{} - {}".format(start_hour,end_hour))
                # Export the plot into a png file
                if export:
                    export_png(p, filename = "{}/{}.png".format(output_dir,output_name))
