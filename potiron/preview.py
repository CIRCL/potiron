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

import argparse
import sys
import os
import glob
import potiron

# Parameters parser
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
# path of the "error" picture to display when there is no preview picture available for a graph
error_picture = "{}doc/error-404.jpg".format(potiron_path)
#maxDay = 0
#month_tab=[]
monthdir = "{}/".format(os.path.abspath(inputdir))
tab_date = monthdir.split('/')[-3:-1]
tab_month = potiron.year
month = tab_month[tab_date[1]]
year = tab_date[0]
f = open("{}index.html".format(monthdir),'w')
# Head of the html preview file
f.write('<!DOCTYPE html>\n<head>\n<title>Preview Index {0} {1}</title>\n<meta charset="utf-8">\
        \n<meta name="viewport" content="width=device-width, initial-scale=1">\
        \n<link rel="stylesheet" href="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/css/bootstrap.min.css">\
        \n<script src="https://ajax.googleapis.com/ajax/libs/jquery/3.2.1/jquery.min.js"></script>\
        \n<script src="https://maxcdn.bootstrapcdn.com/bootstrap/3.3.7/js/bootstrap.min.js"></script>\
        \n</head>\n<body>\n<div class="container">\n<h2>Preview Index {0} {1}</h2>\n'.format(month, year))
# For each day directory in the month directory
for day in sorted(os.listdir(monthdir)):
    daydir = os.path.join(monthdir,day)
    if os.path.isdir(daydir):
        f.write('<div class="row">\n<h3>{}</h3>\n'.format(day))
        # For each hour directory in the day directory
        for hour in sorted(os.listdir(daydir)):
            hourdir = os.path.join(daydir, hour)
            file = glob.glob(hourdir+'/*.png')
            f.write('\t<div class="col-md-4"><div class="thumbnail">\n')
            graph = glob.glob(hourdir+'/*.html')
            f.write('\t\t<a href="{}" target="_blank">\n\t\t\t<div class="caption">\
                    \n\t\t\t\t<p>{}</p>\n\t\t\t</div>\n'.format(graph[0],hour))
            # If .png preview picture exists for the graph, insert it in the index
            if file:
                f.write('\t\t\t<img src="{}" alt="Lights" width="304" height="278">\
                        \n\t\t</a>\n'.format(file[0]))
            # On the other case, insert the error picture
            else:
                f.write('\t\t\t<img src="{}" alt="Lights" width="224" height="224">\
                        \n\t\t</a>\n'.format(error_picture))
            f.write('\t</div></div>\n')
        f.write('</div>\n')
f.write('</div>\n</body>\n</html>\n')
f.close()
