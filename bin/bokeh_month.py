#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import redis
import argparse
import sys
import os
import calendar
import potiron
import export_csv_all_days_per_month
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import Range1d,OpenURL,TapTool,HoverTool,BasicTickFormatter,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool,ColumnDataSource
from bokeh.palettes import Category10_10 as palette
from potiron_graph_annotation import plot_annotation, field2string, create_dict, def_legend
from PIL import Image


plot_width = 1700
plot_height = 900
logo_y_scale = 13


# Define the name of the output file
def output_name(source, field, fieldvalues, date, dest, lentwo):
    value_str = ""
    all_proto = False
    for i in sorted(fieldvalues):
        f = i.split('-')
        if len(f) >= 2:
            if f[1] == "*" or f[1] == "all":
                all_proto = True
                value_str += "_{}".format(f[0])
                continue
        value_str += "_{}".format(i)
    if lentwo and all_proto:
        return "{}{}_{}-{}_{}_with-protocols{}".format(dest,source,date[0:4],date[4:6],field,value_str)
    else:
        return "{}{}_{}-{}_{}{}".format(dest,source,date[0:4],date[4:6],field,value_str)


def process_file(red, source, field, date, fieldvalues, outputdir, logofile, links):
    potiron_path = potiron.potiron_path
    lentwo = False
    for v in fieldvalues:
        # if any field value is in format 'value-protocol' (or 'value-all'), it means we want to display each protocol separatly
        if len(v.split('-')) >= 2:
            lentwo = True
    # Using the format 'value-protocol' is not possible if combined keys are not deployed in the current redis database
    if lentwo and red.sismember('CK', 'NO'):
        sys.stderr.write('Combined keys are not used in this redis dataset')
        sys.exit(1)
    
    if not outputdir.endswith('/'):
        outputdir = "{}/".format(outputdir)
    if not os.path.exists(outputdir):
        os.makedirs(outputdir)
    # Definition of the protocol values and their actual names
    protocols = red.smembers('PROTOCOLS')
    
    # Define the strings used for legends, titles, etc. concerning fields
    field_string, field_in_file_name = field2string(field, potiron_path)
    
    field_data = create_dict(field, potiron_path)
    
    # Creation of the figure and the tools used on it
    namefile=output_name(source,field_in_file_name,fieldvalues,date,outputdir,lentwo)
    all_proto = False
    for fv in fieldvalues:
        v = fv.split('-')
        # If we want to display the values for all the procotols, we display the sum of all of them as well
        if len(v) >= 2 and (v[1] == '*' or v[1] == 'all'):
            all_proto = True
            fieldvalues.append(v[0])
    # As displaying values for all the protocols may generate a lot of lines in the plot, 
    # We help users showing them the protocol when they have there cursor in the line
    if all_proto:
        hover = HoverTool(tooltips = [('count','@y'),('protocol','@protocol')])
    else:
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
    vlength = len(fieldvalues)
    actual_values = []
    nbLine = 0
    day_string = "@x"
    for v in range(vlength): # For each selected field or occurrence
        value = fieldvalues[v].split('-')
        actual_field = value[0]
        if len(value) >= 2: # If we specified a or all protocol(s)
            protocol = value[1]
            if protocol == "*" or protocol == "all":
                for prot in protocols:
                    score=[]
                    dayValue=[]
                    proto = prot.decode()
                    exists = False
                    keys = red.keys("{}:{}:{}*:{}".format(source,proto,date,field))
                    for k in sorted(keys):
                        redisKey = k.decode()
                        day = redisKey.split(':')[2][-2:]
                        countValue = red.zscore(redisKey, actual_field)
                        if countValue is not None:
                            exists = True
                            score.append(countValue)
                        else:
                            score.append(0)
                        dayValue.append(day)
                    if exists:
                        at_least_one = True
                        # We define the color of the line, draw it
                        color = palette[nbLine%10]
                        protos = [proto] * days
                        sourceplot = ColumnDataSource(data=dict(
                                x = dayValue,
                                y = score,
                                protocol = protos
                                ))
                        leg = def_legend(actual_field, proto, field, field_string, field_data)
                        p.line(x='x',y='y',legend=leg,line_color=color,line_width=2,source=sourceplot)
                        c = p.scatter(x='x',y='y',legend=leg,size=10,color=color,alpha=0.1,source=sourceplot)
                        taptool.renderers.append(c)     # In order to have the interaction on click
                        nbLine += 1
                        maxScore = max(score)       # Update the min and max scores scaling
                        if maxVal < maxScore:       # in order to define the lower and upper
                            maxVal = maxScore       # limits for the graph
                        minScore = min(score)
                        if minVal > minScore:
                            minVal = minScore
                        # Definition of the last day for which there is data to display
                        if int(dayValue[-1]) > maxDay:
                            maxDay = int(dayValue[-1])
                        actual_value = "{}-{}".format(actual_field, protocol)
                        actual_values.append(actual_value)
            else:
                score=[]
                dayValue=[]
                exists = False
                keys = red.keys("{}:{}:{}*:{}".format(source,protocol,date,field))
                for k in sorted(keys):
                    redisKey = k.decode()
                    day = redisKey.split(':')[2][-2:]
                    countValue = red.zscore(redisKey, actual_field)
                    if countValue is not None:
                        exists = True
                        score.append(countValue)
                    else:
                        score.append(0)
                    dayValue.append(day)
                if exists: # If at least one occurrence for the current value of field has been found
                    at_least_one = True
                    # We define the color of the line, draw it
                    color = palette[nbLine%10]
                    leg = def_legend(actual_field, protocol, field, field_string, field_data)
                    p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
                    c = p.scatter(x=dayValue,y=score,legend=leg,size=10,color=color,alpha=0.1)
                    taptool.renderers.append(c)     # In order to have the interaction on click
                    nbLine += 1
                    maxScore = max(score)       # Update the min and max scores scaling
                    if maxVal < maxScore:       # in order to define the lower and upper
                        maxVal = maxScore       # limits for the graph
                    minScore = min(score)
                    if minVal > minScore:
                        minVal = minScore
                    # Definition of the last day for which there is data to display
                    if int(dayValue[-1]) > maxDay:
                        maxDay = int(dayValue[-1])
                    actual_value = "{}-{}".format(actual_field, protocol)
                    actual_values.append(actual_value)
        else: # on the other case, we don't split informations for each protocol
            score=[]
            dayValue=[]
            exists = False
            # If combined keys are used, we must by the way take data from all the keys (i.e for each protocol)
            if red.sismember('CK', 'YES'):
                for d in range(1,days+1): # For each day with data stored in redis
                    exists_day = False
                    day = format(d, '02d')
                    countValue = 0
                    keys = red.keys("{}:*:{}{}:{}".format(source,date,day,field))
                    for k in keys:
                        redisKey = k.decode()
                        tmpscore = red.zscore(redisKey, actual_field)
                        countValue += tmpscore if tmpscore is not None else 0
                        exists_day = True
                    if exists_day:
                        if countValue > 0:
                            exists = True
                        score.append(countValue)
                        dayValue.append(day)
            else: # When combined keys are not used, we only need to read the scores for each day
                keys = red.keys("{}:{}*:{}".format(source,date,field))
                for k in sorted(keys):
                    redisKey = k.decode()
                    day = redisKey.split(':')[2][-2:]
                    countValue = red.zscore(redisKey, actual_field)
                    if countValue is not None:
                        exists = True
                        score.append(countValue)
                    else:
                        score.append(0)
                    dayValue.append(day)
            if exists: # If at least one occurrence for the current value of field has been found
                at_least_one = True
                # We define the color of the line, draw it
                color = palette[nbLine%10]
                leg = def_legend(actual_field, None, field, field_string, field_data)
                if all_proto:
                    protos = ['all protocols'] * days
                    sourceplot = ColumnDataSource(data=dict(
                            x = dayValue,
                            y = score,
                            protocol = protos
                            ))
                    p.line(x='x',y='y',legend=leg,line_color=color,line_width=2,source=sourceplot)
                    c = p.scatter(x='x',y='y',legend=leg,size=10,color=color,alpha=0.1,source=sourceplot)
                else:
                    p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
                    c = p.scatter(x=dayValue,y=score,legend=leg,size=10,color=color,alpha=0.1)
                taptool.renderers.append(c)     # In order to have the interaction on click
                nbLine += 1
                maxScore = max(score)       # Update the min and max scores scaling
                if maxVal < maxScore:       # in order to define the lower and upper
                    maxVal = maxScore       # limits for the graph
                minScore = min(score)
                if minVal > minScore:
                    minVal = minScore
                # Definition of the last day for which there is data to display
                if int(dayValue[-1]) > maxDay:
                    maxDay = int(dayValue[-1])
                actual_value = "{}".format(actual_field)
                actual_values.append(actual_value)
    if at_least_one: # If at least one value has been found in redis with our selection
        if lentwo: # Defines the name of the files to call with a click on a point in the plot
            taptool.callback = OpenURL(url="{}_{}_with-protocols_{}-{}-{}.html".format(source,field_in_file_name,date[0:4],date[4:6],day_string))
        else:
            taptool.callback = OpenURL(url="{}_{}_{}-{}-{}.html".format(source,field_in_file_name,date[0:4],date[4:6],day_string))
        output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
        # Definition of some parameters of the graph
        fieldvalues_string = plot_annotation(field, potiron_path, actual_values, field_string, field_data)
        p.title.text = "Number of {} {}seen for each day in {} {}".format(field_string, fieldvalues_string, potiron.year[date[4:6]], date[0:4])
        p.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        p.xaxis.axis_label = "Days"
        p.yaxis.axis_label = "Count"
        p.legend.location = "top_left"
        p.legend.click_policy = "hide"
        # Definition of some parameters for the logo
        with Image.open(logofile) as im :
            im_width, im_height = im.size
        xdr = maxDay + 1
        upper_space = 10
        if nbLine > 2:
            upper_space *= (nbLine / 2)
        ydrmax = maxVal + maxVal * upper_space / 100
        ydrmin = minVal - maxVal * 5 / 100
        p.x_range = Range1d(0,xdr)
        p.y_range = Range1d(ydrmin,ydrmax)
        height = (ydrmax - ydrmin) / logo_y_scale
        width = xdr / ((logo_y_scale * im_height * plot_width) / (im_width * plot_height))
        p.image_url(url=[logofile],x=[xdr],y=[ydrmax-ydrmax*2/100],w=[width],h=[height],anchor="top_right")
        # Process the graph
        save(p)
        if links:
            ck = True if red.sismember('CK', 'YES') else False
            export_csv_all_days_per_month.process_all_files(red, source, date, field, 10, ['-1'], outputdir, True, True, logofile, ck, lentwo)
    else:
        print ("There is no such value for the {} you specified\n".format(field))


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('-s','--source', type=str, nargs=1, help='Sensor used as source (ex: "chp-5890-1")')
    parser.add_argument('-f','--field', type=str, nargs=1, help='Field that should be displayed (ex: "dport")')
    parser.add_argument('-v','--values', nargs='+', help='Specific values of the field to display (ex: "80", "80-tcp", or "80-all" to display all the protocols)')
    parser.add_argument('-d','--date', type=str, nargs=1, help='Date of the informations to display (with the format YYYY-MM)')
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server')
    parser.add_argument('-o','--outputdir', type=str, nargs=1, help='Destination path for the output file')
    parser.add_argument('--logo', type=str, nargs=1, help='Path of the logo file to display')
    parser.add_argument('--links', action='store_true', help='Used if you want to process the graphs usefull to have working links')
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

    if args.outputdir is None: # Destination directory for the output file
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]
    
    if args.logo is None: # Define path of circl logo, based on potiron path
        logofile = "{}doc/circl.png".format(potiron.potiron_path)
    else:
        logofile = args.logo[0]
    
    # If true, export_csv_all_days_per_month module will be called to generate the files pointed by each link
    links = args.links
    
    process_file(red, source, field, date, fieldvalues, outputdir, logofile, links)   
