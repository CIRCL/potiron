
potiron
=======

potiron -  Normalize, Index, Enrich and Visualize Network Capture

potiron is a tool to analyze a series of network capture (pcap) files, parse these with standard tools and normalize
it in JSON format. Then the JSON format is imported into a Redis database to visualize the
normalized information.

The current version potiron supports ipsumdump.

![Potiron web interface](./doc/screenshot.png?raw=true "Potiron web interface")

Requirements
------------

* Python >=3.4
* Flask
* Redis
* ipsumdump

Install
-------

    pip install -r requirements.txt
    cd ./var/www
    bash ./update_thirdparty.sh

Usage
-----

First you need to define a root directory where all the JSON files will be exported. Then you need
to proceed your network capture files to generate the JSON files :

Process with ipsumdump :

	./potiron-json-ipsumpdump.py -c -r /tmp/test-honeypot-1-20140826000000.cap.gz -d ../out/
	potiron[24989]: [INFO] Created filename ../out/2014/08/26/test-honeypot-1-20140826000000.json

Or process with tshark :

	./potiron-json-tshark.py -c -r /tmp/test-honeypot-1-20140826000000.cap.gz -d ../out/
	potiron[24989]: [INFO] Created filename ../out/2014/08/26/test-honeypot-1-20140826000000.json

Then the JSON file can be imported into the Redis database:

	./potiron-redis.py --filename ../out/2014/08/26/test-honeypot-1-20140826000000.json --unix /tmp/redis.sock

Some specific data fields can be represented into graphics (multiple values can be specified after parameter '--value') :

	./bokeh-export.py -s test-honeypot-1 -f dport -v 22 -d 201703 -u /tmp/redis.sock -o ./out/

In order to have working redirections in this plot, the resulting graphs should be created first. To do so, .csv files should be processed :

	./export-csv-all-days-per-month.py -s test-honeypot-1 -f dport -d 201703 -u /tmp/redis.sock -o ./out/ -l 10 --skip -1

The -l parameter is used to define the number of most frequent values to display (default number is 20)
The --skip parameter can be used to specify values to exclude in the graph.

Each one of these files can also be reprocessed separatly:

	./export-csv-day.py -s test-honeypot-1 -f dport -d 20170301 -u /tmp/redis.conf -o ./out/ -l 10 --skip -1

Statistics for an entire month can also be displayed as well. The data file used in this case is created with the following :

	./export-csv-month.py -s test-honeypot-1 -f dport -d 201703 -u /tmp/redis.conf -o ./out/ -l 10 --skip -1

These files contain the data which will be used as data source in the graphs. The next step to do is creating the graphs with the data sources.

	./generate.sh ./out/

The script will simply generate all the .html files using template.html to build the graphs. 
Having both generate.sh and template.html in the same path is recommanded.
The parameter used here is the location of the .csv files, and the .html output files will be created in the same directory.
