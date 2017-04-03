#!/usr/bin/env python3
#    Potiron -  Normalize, Index, Enrich and Visualize Network Capture
#    Copyright (C) 2014 Gerard Wagener
#    Copyright (C) 2014 CIRCL Computer Incident Response Center Luxembourg (smile gie)
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU Affero General Public License as
#    published by the Free Software Foundation, either version 3 of the
#    License, or (at your option) any later version.
#
#    This program is distributed in the hope that it will be useful,
#    but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#    GNU Affero General Public License for more details.
#
#    You should have received a copy of the GNU Affero General Public License
#    along with this program.  If not, see <http://www.gnu.org/licenses/>.

from flask import Flask
from flask import render_template
from flask import send_from_directory
from flask import request
import datetime
import redis
import time
import sys
import os
import configparser
from potiron import get_annotations
from potiron import errormsg
app = Flask(__name__, static_folder='static', static_url_path='/static')

# returns true if all the mandatory fields are set


def check_fields():
    if red.scard("DAYS") > 0:
        if red.scard("FIELDS") > 0:
            return True
    # There was an error
    return False

def check_database():
    if check_fields() == False:
        return "Mandatory fields are missing in the redis database."
    #Take a random day, random field, that was ranked and check if the
    #configured sensorname correspond to the ranked data

    day = red.srandmember("DAYS")
    field = red.srandmember("FIELDS")
    key = sensorname + ":" + day + ":" + field
    if red.exists(key) == False:
        return "The sensorname does not correspond to the data in redis."

    #all checks are fine
    return None

# FIXME to slow to compute at each time?


def get_latest_day():
    if red.exists("DAYS") == False:
        return None
    days = []
    for day in red.smembers("DAYS"):
        days.append(day)
    days.sort()
    return days[-1]


def enum_last_days(today, period):
    days = []
    i = period
    eToday = time.mktime(time.strptime(today, "%Y%m%d"))
    while i >= 0:
        delay = i * 60 * 60 * 24
        seDay = eToday - delay
        sDay = datetime.datetime.fromtimestamp(seDay).strftime("%Y%m%d")
        days.append(sDay)
        i = i - 1
    return days


def get_description(name):
    k = "DS_"+name
    desc = red.get(k)
    if desc is not None:
        return desc
    return ""


def translate_key_human(name, key):
    k = "TR_"+name
    disp_key = red.hget(k, key)
    if disp_key is not None:
        return disp_key
    return key


def translate_human_to_redis(name, key):
    k = "RT_"+name
    disp_key = red.hget(k, key)
    if disp_key is not None:
        return disp_key
    return key

# TODO verify manually if the scores belong to the right keys


def get_recent_evolution(day, field, keys, period):
    out = []
    # Build the legend of the graph
    # lines.append("\"Date,"+",".join(keys)+"\\n\" +\n")
    for day in enum_last_days(day, period):
        # Initialize fixed size array to ensure that the
        # legend order matches the order of scores
        scores = []
        for i in range(0, len(keys)):
            scores.append("0")
        entry = dict()
        i = 0
        for i in range(0, len(keys)):
            ky = keys[i]
            k = sensorname + ":"+day+":"+field
            score = red.zscore(k, ky)
            if score is not None:
                scores[i] = str(score)
            i = i + 1
        entry['day'] = day
        entry['scores'] = ",".join(scores)
        out.append(entry)
    return out


def create_legend(field, top3):
    htop3 = []
    for key in top3:
        htop3.append(translate_key_human(field, key))
    return "Date,"+",".join(htop3)


def get_top_10_per_day(day, fields):
    topdata = []
    for field in fields:
        d = dict()
        d['name'] = field
        d['data'] = []
        d['desc'] = get_description(field)
        k = sensorname + ":" + day + ":" + field
        top3 = []
        # topdata.name
        # topdata.data
        for (key, score) in red.zrevrange(k, 0, 10, 'withscores'):
            if len(top3) < 3:
                top3.append(key)
            entry = dict()
            entry['key'] = translate_key_human(field, key)
            entry['score'] = score
            annotations = get_annotations(red, key, field)
            n = len(annotations)
            if n > 0:
                entry['annot'] = ",".join(annotations)
                entry['anum'] = n
            d['data'].append(entry)
        d['evol'] = get_recent_evolution(day, field, top3, shortcoverage)
        d['legend'] = create_legend(field, top3)
        topdata.append(d)
    return topdata


def create_program_meta():
    desc = dict()
    desc['sensorname'] = sensorname
    desc['version'] = version
    return desc

# Transversal parameters for all the templates


def build_params():
    params = dict()
    # TODO Catch exceptions
    sday = get_latest_day()
    if sday is not None:
        oday = datetime.datetime.strptime(sday, "%Y%m%d")
        nday = oday.strftime("%Y-%m-%d")
        params['today'] = nday
        # Raw format than in redis db
        params['rtoday'] = sday
        params['prefix'] = prefix
    return params


def get_enabled_fields_num():
    x = red.scard("ENFIELDS")
    return x

def check_user_day(day):
    try:
        if day is None:
            return None
        if len(day) > 20:
            raise ValueError("User day string is too large." + day)
        # Let the datetime library check if the parameters correspond to
        # the right date format. If bad parameters are specified,
        # the most recent date is used
        d = datetime.datetime.strptime(day, "%Y-%m-%d")
        day = d.strftime("%Y%m%d")
        #Check if there is data for this day
        if red.sismember("DAYS", day) == 1:
            return day
    except ValueError as error:
        errormsg("check_user_day: "+str(error))
    return None

@app.route('/', methods=['GET', 'POST'])
def welcome():
    try:
        desc = create_program_meta()
        params = build_params()
        emsg = check_database()
        if emsg is not None:
            return render_template('content.html', desc=desc, params=params, emsg=emsg)
        #By default use latest day
        day = get_latest_day()
        if request.method == 'POST':
            p = request.form.get('datepicker')
            #JavaScript Library does also some checks. Do not trust the
            #code running on client machines
            day = check_user_day(p)
            if day is None:
                return render_template('content.html', desc=desc,
                                            params=params, emsg=
                                           "Invalid date specified")
        fields = []
        for field in red.smembers("ENFIELDS"):
            fields.append(field)

        topdata = get_top_10_per_day(day, fields)


        # Convert back the selected date
        d = datetime.datetime.strptime(day, "%Y%m%d")
        selday = d.strftime("%Y-%m-%d")

        # Put a warning when no fields are selected
        if get_enabled_fields_num() == 0:
            emsg = "No data fields are selected. Please select some fields in \
the settings menu."
            return render_template('content.html', desc=desc, fields=fields,
                                    topdata=topdata, params=build_params(),
                                    seldate=selday, emsg=emsg)

        return render_template('content.html', desc=desc, fields=fields,
                            topdata=topdata, params=build_params(),
                            seldate=selday)
    except redis.ConnectionError as err:
        errormsg("Could not connect to redis. "+str(err))
        return render_template('offline.html',prefix=prefix)

#Check if the date delivered by potiron in the overview screen  was not
#tampered in the meantime
def check_date(date):
    try:
        if date is None:
            errormsg("check_date: No date was specified")
            return False
        if len(date) > 20:
            errormsg("check_date: Date field is too large")
            return False
        #Try to parse it. If it fails exception is thrown
        datetime.datetime.strptime(date, "%Y%m%d")
        return True
    except ValueError as e:
        errormsg("check_date: Wrong date format."+str(e))
    return False

#FIXME Verify the field and key parameters too
@app.route('/evolution/<date>/<field>/<key>/')
@app.route('/evolution/<date>/<field>/<key>')
def deliver_evolution(date, field, key):
    try:
        desc = create_program_meta()
        params = build_params()
        if check_date(date) is False:
            emsg="Invalid date specified"
            return render_template('content.html', desc=desc, params=params,
                                   emsg=emsg)
        data = []
        daterange = enum_last_days(date, coverage)
        rkey = translate_human_to_redis(field, key)
        for date in daterange:
            entry = dict()
            k = sensorname+":"+date+":"+field
            score = red.zscore(k, rkey)
            if (score is not None):
                entry['date'] = date
                entry['score'] = score
                data.append(entry)

        # Convert date
        d = datetime.datetime.strptime(date, "%Y%m%d")
        showdate = d.strftime("%Y-%m-%d")
        return render_template("evol.html", desc=desc, date=showdate, field=field,
                               key=key, data=data, params=params)
    except redis.ConnectionError as err:
        errormsg("Cannot connect to redis "+str(err))
        return render_template('offline.html', prefix=prefix)

@app.route('/custom/', methods=['POST'])
@app.route('/custom', methods=['POST'])
def deliver_custom():
    try:
        field = request.form.get("field")
        fieldname = request.form.get("fieldname")
        date = request.form.get("date")
        if field == "" or fieldname == "" or date =="":
            emsg = "An empty parameter was provided."
            errormsg(emsg)
            return render_template('content.html', desc=create_program_meta,
                                    params=build_params(), emsg=emsg)
        # By default the latest day is used. When another date was specified
        # this one is used
        today = get_latest_day()
        if date is not None:
            try:
                d = datetime.datetime.strptime(date, "%Y-%m-%d")
                today = d.strftime("%Y%m%d")
            except ValueError as e:
                errormsg("deliver_custom: Invalid timestamp. "+str(e))
        if red.sismember("FIELDS", fieldname):
            return deliver_evolution(today, fieldname, field)

        emsg = "An invalid parameter was provided"
        return render_template('content.html', desc=create_program_meta,
                                  params=build_params(), emsg=emsg)

    except redis.ConnectionError as err:
        errormsg("deliver_custom: Cannot connect to redis "+str(err))
        return render_template('offline.html', prefix=prefix)

# Deliver all the files in static directory
# TODO ../../../etc/passwd seems not to work
@app.route('/static/<path:filename>')
def send_foo(filename):
    return send_from_directory('static/', filename)


def load_selected_fields():
    fields = []
    for field in red.smembers("FIELDS"):
        k = "ENFIELDS"
        obj = dict()
        obj['name'] = field
        if red.sismember(k, field):
            obj['checked'] = "checked"
        else:
            obj['checked'] = ""
        fields.append(obj)
    return fields

@app.route('/settings/',methods=['POST','GET'])
@app.route('/settings',methods=['POST','GET'])
def send_settings():
    try:
        if request.method == 'POST':
            sfields = request.form.getlist('selectedfields')
            vfields = dict()
            # Check if the fields are valid
            for field in sfields:
                if red.sismember("FIELDS", field):
                    red.sadd("ENFIELDS", field)
                    vfields[field] = True
                # TODO log invalid fields
                # Find checkboxes that were not set or unticketed and remove them
            for f in red.smembers('FIELDS'):
                if (f in vfields) is False:
                    # Found a field that was not selected but is marked as being set
                    # in a previous iteration
                    if red.sismember("ENFIELDS", f):
                        red.srem("ENFIELDS", f)

        fields = load_selected_fields()
        return render_template('settings.html', fields=fields,
                                desc = create_program_meta(),
                                params = build_params())
    except redis.ConnectionError as err:
        errormsg("Cannot connect to redis. "+str(err))
        return render_template('offline.html', prefix=prefix)

if __name__=='__main__':

    try:
        # Load config file
        configfile = "potiron.cfg"
        conf = configparser.ConfigParser()
        if len(sys.argv) != 2:
            sys.stderr.write("[ERROR] A config file must be specified as first\
 command line argument.\n")
            sys.exit(1)
        configfile = sys.argv[1]
        if os.path.exists(configfile) == False:
            sys.stderr.write("[ERROR] Config file was not found.\n")
            sys.exit(1)
        conf.readfp(open(configfile))


        interface = conf.get("dashboard", "interface")
        port = conf.getint("dashboard", "port")
        sensorname = conf.get("dashboard", "sensorname")
        debug = conf.getboolean("dashboard", "debug")
        version = conf.get("dashboard", "version")
        # In order to avoid to large graphs only 6 months of data will be shown
        coverage = conf.getint("dashboard", "coverage")
        usock = conf.get("redis", "unix_socket_path")
        shortcoverage = conf.getint("dashboard", "shortcoverage")
        prefix = conf.get("dashboard", "prefix")
        red = redis.Redis(unix_socket_path=usock)

        app.debug = debug
        app.run(host=interface, port=port)
    except configparser.NoOptionError as e:
        sys.stderr.write("[ERROR] Config corrupted. " + str(e) + "\n")
        sys.exit(1)
    except configparser.NoSectionError as f:
        sys.stderr.write("[ERROR] Config corrupted. " + str(f) + "\n")
        sys.exit(1)
    except ValueError as g:
        sys.stderr.write("[ERROR] Config corrupted?. " + str(g) + "\n")
        sys.exit(1)
