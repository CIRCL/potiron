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

import redis
import argparse
import sys
import os
import calendar
import potiron
import subprocess
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import Range1d,OpenURL,TapTool,HoverTool,BasicTickFormatter,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool,ColumnDataSource
from bokeh.palettes import Category10_10 as palette
from potiron_graph_annotation import plot_annotation, field2string, create_dict, def_legend
from PIL import Image


plot_width = 1700
plot_height = 900
logo_y_scale = 13


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('-s','--source', type=str, nargs=1, help='Sensor used as source (ex: "chp-5890-1")')
    parser.add_argument('-d','--date', type=str, nargs=1, help='Date of the informations to display (with the format YYYY-MM)')
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-o','--outputdir', type=str, nargs=1, help='Destination path for the output file')
    parser.add_argument('--logo', type=str, nargs=1, help='Path of the logo file to display')
    args = parser.parse_args()
    
    # Source sensor
    if args.source is None:
        source = "potiron"
    else:
        source = args.source[0]
    
    # Unix socket to connect to redis-server
    if args.unix is None:
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)
    
    # Define the date of the data to select
    if args.date is None:
        sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
        sys.exit(1)
    date = args.date[0].replace("-","")

    # Destination directory for the output file
    if args.outputdir is None:
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
        if not outputdir.endswith('/'):
            outputdir = "{}/".format(outputdir)
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    
    # Potiron project path
    potiron_path = os.path.dirname(os.path.realpath(__file__))[:-3]
    # Define path of circl logo, based on potiron path
    if args.logo is None:
        logofile = "{}doc/circl.png".format(potiron_path)
    else:
        logofile = args.logo[0]
    
    namefile = '{}{}_{}-{}_arp'.format(outputdir,source,date[0:4],date[4:6])
    output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
    hover = HoverTool(tooltips = [('count','@y')])
    taptool = TapTool()
    TOOLS = [hover,PanTool(),BoxZoomTool(),WheelZoomTool(), taptool, SaveTool(), ResetTool()]
    p = figure(width=plot_width,height=plot_height,tools=TOOLS)
    # Definition of some variables which will be used and modified with the iterations
    at_least_one = False
    days = calendar.monthrange(int(date[0:4]),int(date[4:6]))[1]
    maxVal = 0
    minVal = sys.maxsize
    maxDay = 0
    colors = [palette[0],palette[3]]
    types = ['request','reply']
    for t in types:
        score = []
        dayValue = []
        exists = False
        for d in range(1,days+1):
            day = format(d, '02d')
            redisKey = "{}_{}{}_count".format(source,date,day)
            if red.exists(redisKey):
                countValue = red.zscore(redisKey,t)
                if countValue is not None:
                    exists = True
                    score.append(countValue)
                else:
                    score.append(0)
                dayValue.append(day)
        if exists:
            at_least_one = True
            color = colors[types.index(t)]
            leg = t
            p.line(x=dayValue, y=score, legend=leg, line_color=color, line_width=2)
            p.scatter(x=dayValue, y=score, legend=leg, size=10, color=color, alpha=0.1)
            maxScore = max(score)       # Update the min and max scores scaling
            if maxVal < maxScore:       # in order to define the lower and upper
                maxVal = maxScore       # limits for the graph
            minScore = min(score)
            if minVal > minScore:
                minVal = minScore
            # Definition of the last day for which there is data to display
            if int(dayValue[-1]) > maxDay:
                maxDay = int(dayValue[-1])
    if at_least_one:
        output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
        p.title.text = "Number of ARP packets seen on {} for each day in {} {}".format(source,potiron.year[date[4:6]], date[0:4])
        p.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p.legend.location = "top_left"
        p.legend.click_policy = "hide"
        # Definition of some parameters for the logo
        with Image.open(logofile) as im :
            im_width, im_height = im.size
        xdr = maxDay + 1
        upper_space = 10
        ydrmax = maxVal + maxVal * upper_space / 100
        ydrmin = minVal - maxVal * 5 / 100
        p.x_range = Range1d(0,xdr)
        p.y_range = Range1d(ydrmin,ydrmax)
        height = (ydrmax - ydrmin) / logo_y_scale
        width = xdr / ((logo_y_scale * im_height * plot_width) / (im_width * plot_height))
        p.image_url(url=[logofile],x=[xdr],y=[ydrmax],w=[width],h=[height],anchor="top_right")
        # Process and display the graph
        save(p)
    
