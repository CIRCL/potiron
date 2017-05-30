
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

For all the following graphs, the parameters used are :

* -s, the honeypot source where the data come from
* -f, the field related to the informations you want to display
* -d, the date on which the informations have been collected
* -o, the output directory
* -u, the unix socket used open the redis client
* -r, the pcap files read in input

First you need to define a root directory where all the JSON files will be exported. Then you need
to proceed your network capture files to generate the JSON files :

Process with ipsumdump :

	./potiron-json-ipsumpdump.py -c -i /tmp/test-honeypot-1-20140826000000.cap.gz -o ../out/
	potiron[24989]: [INFO] Created filename ../out/2014/08/26/test-honeypot-1-20140826000000.json

Or process with tshark :

	./potiron-json-tshark.py -c -i /tmp/test-honeypot-1-20140826000000.cap.gz -o ../out/
	potiron[24989]: [INFO] Created filename ../out/2014/08/26/test-honeypot-1-20140826000000.json

Then the JSON file can be imported into the Redis database:

	./potiron-redis.py --filename ../out/2014/08/26/test-honeypot-1-20140826000000.json --unix /tmp/redis.sock

Some specific data fields can be represented into graphics (multiple values can be specified after parameter '-v') :

	./bokeh-export.py -s test-honeypot-1 -f dport -v 22 -d 201703 -u /tmp/redis.sock -o ./out/ --logo /home/user/Pictures/logo.png

The last parameter --logo is optionnal and is the ABSOLUTE path of the logo file which will be displayed. If no argument is given, the default file is the CIRCL logo stored in the doc/ directory of potiron.

In order to have working redirections in this plot, the resulting graphs should be created first. To do so, .csv files should be processed :

	./export-csv-all-days-per-month.py -s test-honeypot-1 -f dport -d 201703 -u /tmp/redis.sock -o ./out/ -l 10 --skip -1

The -l parameter is used to define the number of most frequent values to display (default number is 20)
The --skip parameter can be used to specify values to exclude in the graph.

Each one of these files can also be reprocessed separatly:

	./export-csv-day.py -s test-honeypot-1 -f dport -d 20170301 -u /tmp/redis.conf -o ./out/ -l 10 --skip -1

Statistics for an entire month can also be displayed as well. The data file used in this case is created with the following :

	./export-csv-month.py -s test-honeypot-1 -f dport -d 201703 -u /tmp/redis.conf -o ./out/ -l 10 --skip -1

These files contain the data which will be used as data source in the graphs. The next step to do is creating the graphs with the data sources.

	./generate.sh ./out/ /home/user/Pictures/logo.png

The script will simply generate all the .html files using template.html to build the graphs. 
Having both generate.sh and template.html in the same path is recommanded.
The first parameter used here is the location of the .csv files, and the .html output files will be created in the same directory. The second parameter is optionnal and is the absolute path of the logo file which will be displayed. If no argument is given, the default path is the same used for the bokeh graph, which is the CIRCL logo stored in the doc/ directory of potiron.


Summary
-------

* Usual potiron functionalities :
	- potiron-json-ipsumdump / potiron-json-tshark : create json files from pcap files
		- input : pcap files
		- output : corresponding json files
	- potiron-redis : stores data from json files in redis
		- input : json files
		- output : redis
	- bokeh-export : process graphs to display specific values of a field for a month
		- input : redis data
		- output : bokeh plot
	- export-csv-* : process datafiles for the graphs of the most frequent values of a field, the period depends on the parameter specified in the * caracter's place
		- input : redis data
		- output : csv data files
	- generate : creates graphs corresponding to the csv files, using template.html as the template of the graph
		- input : csv data files
		- output : d3.js bubble charts

	- potiron_graph_annotation is used to put the real name of the fields / values displayed in the graphs, instead of their variable name, using dictionaries stored in "doc" directory

* Additionnal functionalities :
	- isn-pcap / isn-pcap-process-day : use pcap files to process graphs of the sequence and acknowledgement numbers over time, with the destination port indicated as the color of the dots
		- input : pcap files
		- output : ISN graphs
	- potiron-isn-redis : stores data from json files in a time series redis structure in order to process ISN graphs directly from redis
		- input : json files
		- output : redis
	- isn-redis / isn-redis-process-day : process ISN graphs with data from redis 
		- input : redis data
		- output : ISN graphs

	- parallel-coordinate : process csv files containing data used to display parallel coordinates of the daily most frequent values of a field for a month
		- input : redis data
		- output : csv data files
	- generate-pc : creates parallel coordinate graphs with the csv files, using template-pc.html as template
		- input : csv data files
		- output : d3.js parallel coordinate graphs
