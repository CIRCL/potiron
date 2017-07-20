#!/usr/bin/env python3
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


# Define the name of the output file
def output_name(source, field, fieldvalues, date, dest):
    value_str = ""
    for i in sorted(fieldvalues):
        value_str = value_str + "_" + i
    return "{}{}_{}-{}_{}{}".format(dest,source,date[0:4],date[4:6],field,value_str)


def generate_links(source, field, date, outputdir, usocket, logofile):
    csv = './export-csv-all-days-per-month.py -s {} -d {}-{} -f {} -o {} -u {} -g --logo {} --links'.format(
            source, date[0:4], date[4:6], field, outputdir, usocket, logofile)
    proc_csv = subprocess.Popen(csv, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    proc_csv.wait()


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('-s','--source', type=str, nargs=1, help='Data source')
    parser.add_argument('-f','--field', type=str, nargs=1, help='Field that should be displayed.')
    parser.add_argument('-v','--values', nargs='+', help='Specific values of the field to display')
    parser.add_argument('-d','--date', type=str, nargs=1, help='Date of the informations to display')
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-o','--outputdir', type=str, nargs=1, help='Destination path for the output file')
    parser.add_argument('--logo', type=str, nargs=1, help='Path of the logo file to display')
    parser.add_argument('--links', action='store_true', help='Used if you want to process the graphs usefull to have working links')
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

    # Define the date of the data to select
    if args.date is None:
        sys.stderr.write('A date must be specified.\nThe format is : YYYY-MM\n')
        sys.exit(1)
    date = args.date[0].replace("-","")

    # Define the occurrences to select for the given field
    if args.values is None:
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
        
    links = args.links
        
    # Definition of the protocol values and their actual names
    protocols_path = "{}doc/protocols".format(potiron_path)
    protocols = potiron.define_protocols(protocols_path)

    # Define the strings used for legends, titles, etc. concerning fields
    field_string, field_in_file_name = field2string(field, potiron_path)
    
    field_data = create_dict(field, potiron_path)
    
    # Creation of the figure and the tools used on it
    namefile=output_name(source,field_in_file_name,fieldvalues,date,outputdir)
    output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
    hover = HoverTool(tooltips = [('count','@y'),('protocol','@protocol')])
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
    # For each selected field or occurrence
    for v in range(vlength):
        value = fieldvalues[v].split('-')
        actual_field = value[0]
        #
        if len(value) == 2:
            protocol = value[1]
            if protocol == "*" or protocol == "all":
                for prot in protocols:
                    score=[]
                    dayValue=[]
                    proto = protocols[prot]
                    exists = False
                    # For each day with data stored in redis
                    for d in range(1,days+1):
                        day = format(d, '02d')
                        redisKey = "{}:{}:{}{}:{}".format(source,proto,date,day,field)
                        if red.exists(redisKey):
                            # If the key exists, we find in redis the score of the fieldvalue we want and put it in the list of scores
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
#                        p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
#                        c = p.scatter(x=dayValue,y=score,legend=leg,size=10,color=color,alpha=0.1)
                        day_string = "@x"
                        taptool.renderers.append(c)     # In order to have the interaction on click
#                        proto = "@protocol"
                        taptool.callback = OpenURL(url="{}_{}_{}-{}-{}.html".format(source,field_in_file_name,date[0:4],date[4:6],day_string))
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
                # For each day with data stored in redis
                for d in range(1,days+1):
                    day = format(d, '02d')
                    redisKey = "{}:{}:{}{}:{}".format(source,protocol,date,day,field)
                    if red.exists(redisKey):
                        # If the key exists, we find in redis the score of the fieldvalue we want and put it in the list of scores
                        countValue = red.zscore(redisKey, actual_field)
                        if countValue is not None:
                            exists = True
                            score.append(countValue)
                        else:
                            score.append(0)
                        dayValue.append(day)
                # If at least one occurrence for the current value of field has been found
                if exists:
                    at_least_one = True
                    # We define the color of the line, draw it
                    color = palette[nbLine%10]
                    leg = def_legend(actual_field, protocol, field, field_string, field_data)
                    p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
                    c = p.scatter(x=dayValue,y=score,legend=leg,size=10,color=color,alpha=0.1)
                    taptool.renderers.append(c)     # In order to have the interaction on click
                    taptool.callback = OpenURL(url="{}_{}_{}_{}-{}-@x".format(source,field_in_file_name,protocol,date[0:4],date[4:6]))
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
            if red.sismember('CK', 'YES'):
                # For each day with data stored in redis
                for d in range(1,days+1):
                    exists_day = False
                    day = format(d, '02d')
                    countValue = 0
                    for prot in protocols:
                        redisKey = "{}:{}:{}{}:{}".format(source,protocols[prot],date,day,field)
                        if red.exists(redisKey):
                            tmpscore = red.zscore(redisKey, actual_field)
                            # If the key exists, we find in redis the score of the fieldvalue we want and put it in the list of scores
                            countValue += tmpscore if tmpscore is not None else 0
                            exists_day = True
                    if exists_day:
                        if countValue > 0:
                            exists = True
                        score.append(countValue)
                        dayValue.append(day)
            else:
                # For each day with data stored in redis
                for d in range(1,days+1):
                    day = format(d, '02d')
                    redisKey = "{}:{}{}:{}".format(source,date,day,field)
                    if red.exists(redisKey):
                        countValue = red.zscore(redisKey, actual_field)
                        if countValue is not None:
                            exists = True
                            score.append(countValue)
                        else:
                            score.append(0)
                        dayValue.append(day)
            # If at least one occurrence for the current value of field has been found
            if exists:
                at_least_one = True
                # We define the color of the line, draw it
                color = palette[nbLine%10]
                leg = def_legend(actual_field, None, field, field_string, field_data)
                p.line(x=dayValue,y=score,legend=leg,line_color=color,line_width=2)
                c = p.scatter(x=dayValue,y=score,legend=leg,size=10,color=color,alpha=0.1)
                taptool.renderers.append(c)     # In order to have the interaction on click
                taptool.callback = OpenURL(url="{}_{}_{}-{}-@x".format(source,field_in_file_name,date[0:4],date[4:6]))
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
    # If at least one value has been found in redis with our selection
    if at_least_one:
        output_file("{}.html".format(namefile), title=namefile.split("/")[-1])
        # Definition of some parameters of the graph
        fieldvalues_string = plot_annotation(field, potiron_path, actual_values, field_string, field_data)
        p.title.text = "Number of {} {}seen for each day in {} {}".format(field_string, fieldvalues_string, potiron.year[date[4:6]], date[0:4])
        p.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
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
        p.image_url(url=[logofile],x=[xdr],y=[ydrmax],w=[width],h=[height],anchor="top_right")
        # Process and display the graph
        save(p)
        if links:
            generate_links(source, field, date, outputdir, usocket, logofile)
    else:
        print ("There is no such value for the {} you specified\n".format(field))
