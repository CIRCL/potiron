#!/usr/bin/env python3
import redis
import argparse
import sys
import os
import calendar
from bokeh.plotting import figure, show, output_file, save
from bokeh.models import Range1d,OpenURL,TapTool,HoverTool,BasicTickFormatter,PanTool, BoxZoomTool,ResetTool,SaveTool,WheelZoomTool
from bokeh.palettes import Category10_10 as palette
from potiron_graph_annotation import plot_annotation
from PIL import Image


plot_width = 1500
plot_height = 800
logo_y_scale = 12


# Define the name of the output file
def output_name(source, field, fieldvalues, date, dest):
    value_str = ""
    for i in sorted(fieldvalues):
        value_str = value_str + "_" + i
    return "{}{}_{}-{}_{}{}".format(dest,source,date[0:4],date[4:6],field,value_str)


if __name__ == '__main__':
    # Parameters parser
    parser = argparse.ArgumentParser(description='Export redis values in a graph.')
    parser.add_argument('-s','--source', type=str, nargs=1, help='Data source')
    parser.add_argument('-f','--field', type=str, nargs=1, help='Field that should be displayed.')
    parser.add_argument('-v','--values', nargs='+', help='Specific values of the field to display')
    parser.add_argument('-d','--date', type=str, nargs=1, help='Date of the informations to display')
    parser.add_argument('-u','--unix', type=str, nargs=1, help='Unix socket to connect to redis-server.')
    parser.add_argument('-o','--outputdir', type=str, nargs=1, help='Destination path for the output file')
    parser.add_argument('-ck', '--combined_keys', action='store_true', help='In case of combined redis keys')
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
        sys.stderr.write('A date must be specified.\nThe format is : YYYYMM')
        sys.exit(1)
    date = args.date[0]

    # Define the occurrences to select for the given field
    if args.values is None:
        sys.stderr.write('At least one value must be specified\n')
        sys.exit(1)
    fieldvalues = args.values

    # Destination directory for the output file
    if args.outputdir is None:
        outputdir = "./out/"
    else:
        outputdir = args.outputdir[0]

    # In case of combined redis keys
    ck = args.combined_keys

    # Define path of circl logo, based on potiron path
    potiron_path = os.path.dirname(os.path.realpath(__file__))[:-3]
    if args.logo is None:
        logofile = "{}doc/circl.png".format(potiron_path)
    else:
        logofile = args.logo[0]

    # Define the strings used for legends, titles, etc.
    field_string, field_in_file_name, fieldvalues_string, leg = plot_annotation(field, fieldvalues, potiron_path)

    # Creation of the figure and the tools used on it
    namefile=output_name(source,field_in_file_name,fieldvalues,date,outputdir)
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
    # For each selected occurrence of the field
    for v in range(len(fieldvalues)):
        score=[]
        dayValue=[]
        exists = False
        value = fieldvalues[v].split('-')
        # For each day with data stored in redis
        for d in range(1,days+1):
            day = False
            if ck:
                if len(value) == 2:
                    redisKey = "{}:{}{}:{}:{}".format(source, date, format(d, '02d'), field, value[1])
                    if red.exists(redisKey):
                        # If the key exists, we find in redis the score of the fieldvalue we want and put it in the list of scores
                        countValue = red.zscore(redisKey, value[0])
                        day = True
                else:
                    countValue = 0
                    for po in ["tcp","udp"]:
                        redisKey = "{}:{}{}:{}:{}".format(source,date,format(d,'02d'), field, po)
                        if red.exists(redisKey):
                            tmp = red.zscore(redisKey, fieldvalues[v])
                            if tmp is not None:
                                countValue += tmp
                            day = True
            else:
                redisKey = "{}:{}{}:{}".format(source, date,format(d,'02d'),field)
                if red.exists(redisKey):
                    countValue = red.zscore(redisKey, fieldvalues[v])
                    day = True
            if day:
                exists = True
                score.append(countValue if countValue is not None else 0)
                dayValue.append(format(d, '02d'))
        # Definition of the last day for which there is data to display
        if int(dayValue[-1]) > maxDay:
            maxDay = int(dayValue[-1])
        # If at least one occurrence for the current value of field has been found
        if exists:
            # We define the color of the line, draw it
            color = palette[v%10]
            p.line(x=dayValue,y=score,legend=leg[v],line_color=color,line_width=2)
            c = p.scatter(x=dayValue,y=score,legend=leg[v],size=10,color=color,alpha=0.1)
            taptool.renderers.append(c)     # In order to have the interaction on click
            at_least_one = True
            maxScore = max(score)       # Update the min and max scores scaling
            if maxVal < maxScore:       # in order to define the lower and upper
                maxVal = maxScore       # limits for the graph
            minScore = min(score)
            if minVal > minScore:
                minVal = minScore
    # If at least one value has been found in redis with our selection
    if at_least_one:
        # Definition of some parameters of the graph
        p.title.text = "Number of {} {}seen for each day on month {}, year {}".format(field_string, fieldvalues_string, date[4:6], date[0:4])
        p.yaxis[0].formatter = BasicTickFormatter(use_scientific=False)
        day = "@x"
        taptool.callback = OpenURL(url="{}_{}_{}-{}-{}.html".format(source,field_in_file_name,date[0:4],date[4:6],day))
        p.legend.location = "top_left"
        p.legend.click_policy = "hide"
        # Definition of some parameters for the logo
        with Image.open(logofile) as im :
            im_width, im_height = im.size
        xdr = maxDay + 1
        ydrmax = maxVal + maxVal * 10 / 100
        ydrmin = minVal - maxVal * 5 / 100
        p.x_range = Range1d(0,xdr)
        p.y_range = Range1d(ydrmin,ydrmax)
        height = (ydrmax - ydrmin) / logo_y_scale
        width = xdr / ((logo_y_scale * im_height * plot_width) / (im_width * plot_height))
        p.image_url(url=[logofile],x=[xdr],y=[ydrmax],w=[width],h=[height],anchor="top_right")
        # Process and display the graph
        save(p)
    else:
        print ("There is no such value for the {} you specified\n".format(field))
