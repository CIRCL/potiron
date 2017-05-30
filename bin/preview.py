#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue May 30 14:27:47 2017

@author: student
"""

import argparse
import sys
import os
import glob

parser = argparse.ArgumentParser(description='Index of all the previews of ISN graphs')
parser.add_argument('-i', '--input', type=str, nargs=1, help='Input directory')
parser.add_argument('-o', '--output', type=str, nargs=1, help='Output directory')
args = parser.parse_args()

if args.input is None:
    sys.stderr.write("An input directory must be specified.\n")
    sys.exit(1)
inputdir = args.input[0]

if args.output is None:
    outputdir = inputdir
else:
    outputdir = args.output[0]

potiron_path = os.path.dirname(os.path.realpath(__file__))[:-3]
error_picture = "{}doc/error-404.jpg".format(potiron_path)
#maxDay = 0
#month_tab=[]
monthdir = "{}/".format(os.path.abspath(inputdir))
f = open("{}index.html".format(monthdir),'w')
f.write('<!DOCTYPE html>\n<head>\n<title>Preview Index</title>\n<meta charset="utf-8">\
        \n<meta name="viewport" content="width=device-width, initial-scale=1">\
        \n<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">\
        \n<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>\
        \n<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>\
        \n</head>\n<body>\n<div class="container">\n<h2>Preview Index</h2>\n')
for day in sorted(os.listdir(monthdir)):
#    day_tab=[]
    daydir = os.path.join(monthdir,day)
    if os.path.isdir(daydir):
        f.write('<div class="row">\n<h3>{}</h4>\n'.format(day))
        for hour in sorted(os.listdir(daydir)):  
            hourdir = os.path.join(daydir, hour)
            file = glob.glob(hourdir+'/*.png')
            f.write('\t<div class="col-md-4"><div class="thumbnail">\n')
            if file:
                graph = glob.glob(hourdir+'/*.html')
                f.write('\t\t<a href="{}" target="_blank">\n\t\t\t<div class="caption">\n\t\t\t\t<p>{}</p>\
                        \n\t\t\t</div>\n\t\t\t<img src="{}" alt="Lights" width="304" height="278">\
                        \n\t\t</a>\n'.format(graph[0],hour,file[0]))
            else:
                f.write('\t\t<div class="caption">\n\t\t\t<p>{}</p>\n\t\t</div>\
                        \n\t\t<img src="{}" alt="Lights" width="224" height="224">\n'.format(hour,error_picture))
            f.write('\t</div></div>\n')
        f.write('</div>\n')
f.write('</div>\n</body>\n</html>\n')
f.close()