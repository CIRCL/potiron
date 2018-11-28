#!/usr/bin/env python3
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
import potiron
import calendar
from datetime import datetime as dt
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import Range1d,OpenURL,TapTool,HoverTool,BasicTickFormatter,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool,ColumnDataSource
from bokeh.palettes import Category10_10 as palette
from potiron_graph_annotation import plot_annotation, field2string, create_dict, def_legend
from PIL import Image

potiron_path = potiron.potiron_path
plot_width = 1700
plot_height = 900
logo_y_scale = 13

def output_name(outputdir, source, date, field_in_file_name, fieldvalues):
    value_str = ""
    written = []
    for i in sorted(fieldvalues):
        f = i.split('-')
        if len(f) >= 2:
            if (f[1] == "*" or f[1] == "all") and f[0] not in written:
                value_str += "_{}".format(f[0])
                written.append(f[0])
        else:
            if i not in written:
                value_str += "_{}".format(i)
                written.append(i)
    if lentwo and all_proto:
        return "{}{}_{}-{}_{}_with-protocols{}".format(outputdir, source, date[0], date[-1], field_in_file_name, value_str)
    else:
        return "{}{}_{}-{}_{}{}".format(outputdir, source, date[0], date[-1], field_in_file_name, value_str)
    

def tab_date(date, timeline):
    timeline -= 1
    y = int(date[0:4])
    m = int(date[4:6])
    newmonth = ((m - 1 - timeline) % 12) + 1
    diff = 1 if timeline >= m else 0
    diff += int((timeline - m) / 12)
    newyear = y - diff
    newdate = "{}{}".format(format(newyear, '02d'), format(newmonth, '02d'))
    tab = [newdate]
    while newdate != date:
        newmonth = newmonth % 12 + 1
        if newmonth == 1:
            newyear += 1
        newdate = "{}{}".format(format(newyear, '02d'), format(newmonth, '02d'))
        tab.append(newdate)
    return tab


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('-s','--source', type=str, nargs=1, help='Sensor used as source (ex: "chp-5890-1")')
    parser.add_argument('-f','--field', type=str, nargs=1, help='Field that should be displayed (ex: "dport")')
    parser.add_argument('-v','--values', nargs='+', help='Specific values of the field to display (ex: "80", "80-tcp", or "80-all" to display all the protocols)')
    parser.add_argument('-d','--date', type=str, nargs=1, help='Date of the informations to display (with the format YYYY)')
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-o','--outputdir', type=str, nargs=1, help='Destination path for the output file')
    parser.add_argument('--logo', type=str, nargs=1, help='Path of the logo file to display')
#    parser.add_argument('--links', action='store_true', help='Can be used if you want to process the graphs usefull to have working links')
    parser.add_argument('-tl', '--timeline', type=str, nargs=1, help='Used to define the duration of the sample to display')
    args = parser.parse_args()
    
    if args.source is None: # Source sensor
        source = "potiron"
    else:
        source = args.source[0]

    if args.unix is None: # Unix socket to connect to redis-server
        sys.stderr.write('A Unix socket must be specified.\n')
        sys.exit(1)
    usocket = args.unix[0]
    red = redis.Redis(unix_socket_path=usocket)

    # Define the fields available in redis
    members=""
    tab_members=[]
    for i in red.smembers('FIELDS'):
        val = i.decode()
        members = members + val + ", "
        tab_members.append(val)
    members=members[:-2]

    # If no field is given in parameter, or if the field given is not in the fields in redis, the module stops
    if args.field is None:
        sys.stderr.write('A field must be specified.\nChoose one of these : {}.\n'.format(members))
        sys.exit(1)
    if args.field[0] not in tab_members:
        sys.stderr.write('The field you chose does not exist.\nChoose one of these : {}.\n'.format(members))
        sys.exit(1)
    field = args.field[0]

    if args.date is None: # Define the date of the data to select
        sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
        sys.exit(1)
    date = args.date[0].replace("-","")

    if args.values is None: # Define the occurrences to select for the given field
        sys.stderr.write('At least one value must be specified\n')
        sys.exit(1)
    fieldvalues = args.values
    lentwo = False
    for v in fieldvalues:
        if len(v.split('-')) == 2:
            lentwo = True
    if lentwo and red.sismember('CK', 'NO'):
        sys.stderr.write('Combined keys are not used in this redis dataset')
        sys.exit(1)

    if args.outputdir is None: # Destination directory for the output file
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
    if not outputdir.endswith('/'):
        outputdir = "{}/".format(outputdir)
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)

    if args.logo is None: # Define path of circl logo, based on potiron path
        logofile = "{}doc/circl.png".format(potiron_path)
    else:
        logofile = args.logo[0]
    
    if args.timeline is None:
        timeline = 6
    else:
        timeline = int(args.timeline[0])
    
    # If true, export_csv_all_days_per_month module will be called to generate the files pointed by each link
#    links = args.links
    
    # Define the strings used for legends, titles, etc. concerning fields
    field_string, field_in_file_name = field2string(field, potiron_path)
    field_data = create_dict(field, potiron_path)
    
    potiron_path = potiron.potiron_path
    ck = red.sismember('CK', 'YES')
    lentwo = False
    all_proto = False
    for fv in fieldvalues:
        v = fv.split('-')
        # if any field value is in format 'value-protocol' (or 'value-all'), it means we want to display each protocol separatly
        if len(v) >= 2 :
            lentwo = True
            # If we want to display the values for all the procotols, we display the sum of all of them as well
            if v[1] == '*' or v[1] == 'all':
                all_proto = True
                fieldvalues.append(v[0])
    # Using the format 'value-protocol' is not possible if combined keys are not deployed in the current redis database
    if lentwo and not ck:
        sys.stderr.write('Combined keys are not used in this redis dataset')
        sys.exit(1)
    
    # Definition of the protocols currently present in our dataset
    protocols = red.smembers('PROTOCOLS')
    tab_date = tab_date(date, timeline)
    namefile = output_name(outputdir, source, tab_date, field_in_file_name, fieldvalues)
    
    if all_proto:
        hover = HoverTool(tooltips = [('count','@y'),('protocol','@protocol')])
    else:
        hover = HoverTool(tooltips = [('count','@y')])
    taptool = TapTool()
    TOOLS = [hover,PanTool(),BoxZoomTool(),WheelZoomTool(), taptool, SaveTool(), ResetTool()]
    p = figure(width=plot_width,height=plot_height,tools=TOOLS,x_axis_type="datetime")
    # Definition of some variables which will be used and modified with the iterations
    at_least_one = False
    maxVal = 0
    minVal = sys.maxsize
    vlength = len(fieldvalues)
    actual_values = []
    nbLine = 0
    day_string = "@x"
    for v in range(vlength): # For each selected field or occurrence
        value = fieldvalues[v].split('-')
        actual_field = value[0]
        if len(value) >= 2:
            protocol = value[1]
            if protocol == "*" or protocol == "all":
                for prot in protocols:
                    score = []
                    dayValue = []
                    proto = prot.decode()
                    exists = False
                    for dateval in tab_date:
                        keys = red.keys("{}:{}:{}*:{}".format(source, proto, dateval, field))
                        year = dateval[0:4]
                        month = dateval[4:6]
                        for k in sorted(keys):
                            redisKey = k.decode()
                            day = redisKey.split(':')[2][-2:]
                            countValue = red.zscore(redisKey, actual_field)
                            if countValue is not None:
                                exists = True
                                score.append(countValue)
                            else:
                                score.append(0)
                            dayval = "{}-{}-{}".format(year, month, day)
                            dayValue.append(dt.strptime(dayval, "%Y-%m-%d"))
                    if exists:
                        at_least_one = True
                        # We define the color of the line, draw it
                        color = palette[nbLine%10]
                        protos = [proto] * len(score)
                        sourceplot = ColumnDataSource(data=dict(
                                x = dayValue,
                                y = score,
                                protocol = protos
                                ))
                        leg = def_legend(actual_field, proto, field, field_string, field_data)
                        p.line(x='x',y='y',legend=leg,line_color=color,line_width=2,source=sourceplot)
                        nbLine += 1
                        maxScore = max(score)       # Update the min and max scores scaling
                        if maxVal < maxScore:       # in order to define the lower and upper
                            maxVal = maxScore       # limits for the graph
                        minScore = min(score)
                        if minVal > minScore:
                            minVal = minScore
                        actual_value = "{}-{}".format(actual_field, protocol)
                        actual_values.append(actual_value)
            else:
                score=[]
                dayValue=[]
                exists = False
                for dateval in tab_date:
                    keys = red.keys("{}:{}:{}*:{}".format(source, protocol, dateval, field))
                    year = dateval[0:4]
                    month = dateval[4:6]
                    for k in sorted(keys):
                        redisKey = k.decode()
                        day = redisKey.split(':')[2][-2:]
                        countValue = red.zscore(redisKey, actual_field)
                        if countValue is not None:
                            exists = True
                            score.append(countValue)
                        else:
                            score.append(0)
                        dayval = "{}-{}-{}".format(year, month, day)
                        dayValue.append(dt.strptime(dayval, "%Y-%m-%d"))
                if exists: # If at least one occurrence for the current value of field has been found
                    at_least_one = True
                    # We define the color of the line, draw it
                    color = palette[nbLine%10]
                    leg = def_legend(actual_field, protocol, field, field_string, field_data)
                    p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
                    nbLine += 1
                    maxScore = max(score)       # Update the min and max scores scaling
                    if maxVal < maxScore:       # in order to define the lower and upper
                        maxVal = maxScore       # limits for the graph
                    minScore = min(score)
                    if minVal > minScore:
                        minVal = minScore
                    actual_value = "{}-{}".format(actual_field, protocol)
                    actual_values.append(actual_value)
        else: # on the other case, we don't split informations for each protocol
            score=[]
            dayValue=[]
            exists = False
            # If combined keys are used, we must by the way take data from all the keys (i.e for each protocol)
            if ck:
                for m in tab_date:
                    days = calendar.monthrange(int(m[0:4]),int(m[4:6]))[1]
                    year = m[0:4]
                    month = m[4:6]
                    for d in range(1,days+1):
                        exists_day = False
                        day = format(d, '02d')
                        countValue = 0
                        keys = red.keys("{}:*:{}{}{}:{}".format(source,year,month,day,field))
                        for k in keys:
                            redisKey = k.decode()
                            tmpscore = red.zscore(redisKey, actual_field)
                            countValue += tmpscore if tmpscore is not None else 0
                            exists_day = True
                        if exists_day:
                            if countValue > 0:
                                exists = True
                            score.append(countValue)
                            dayval = "{}-{}-{}".format(year, month, day)
                            dayValue.append(dt.strptime(dayval, "%Y-%m-%d"))
            else: # When combined keys are not used, we only need to read the scores for each day
                for dateval in tab_date:
                    keys = red.keys("{}:{}*:{}".format(source,dateval,field))
                    year = dateval[0:4]
                    month = dateval[4:6]
                    for k in sorted(keys):
                        redisKey = k.decode()
                        day = redisKey.split(':')[2][-2:]
                        countValue = red.zscore(redisKey, actual_field)
                        if countValue is not None:
                            exists = True
                            score.append(countValue)
                        else:
                            score.append(0)
                        dayval = "{}-{}-{}".format(year, month, day)
                        dayValue.append(dt.strptime(dayval, "%Y-%m-%d"))
            if exists:
                at_least_one = True
                # We define the color of the line, draw it
                color = palette[nbLine%10]
                leg = def_legend(actual_field, None, field, field_string, field_data)
                if all_proto:
                    protos = ['all protocols'] * len(score)
                    sourceplot = ColumnDataSource(data=dict(
                            x = dayValue,
                            y = score,
                            protocol = protos
                            ))
                    p.line(x='x',y='y',legend=leg,line_color=color,line_width=2,source=sourceplot)
                else:
                    p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
                nbLine += 1
                maxScore = max(score)       # Update the min and max scores scaling
                if maxVal < maxScore:       # in order to define the lower and upper
                    maxVal = maxScore       # limits for the graph
                minScore = min(score)
                if minVal > minScore:
                    minVal = minScore
                actual_value = "{}".format(actual_field)
                actual_values.append(actual_value)
    if at_least_one:
        output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
        fieldvalues_string = plot_annotation(field, potiron_path, actual_values, field_string, field_data)
        p.title.text = "Number of {} {}seen each day between {} {} and {} {}".format(field_string, fieldvalues_string, 
                                  potiron.year[tab_date[0][4:6]], tab_date[0][0:4], potiron.year[tab_date[-1][4:6]], tab_date[-1][0:4])
        p.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p.xaxis.axis_label = "Date"
        p.yaxis.axis_label = "Count"
        p.legend.location = "top_left"
        p.legend.click_policy = "hide"
        # Process the graph
        save(p)
    else:
        print ("There is no such value for a {} you specified: {}".format(field_string,fieldvalues))
        
