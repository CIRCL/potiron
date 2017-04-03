
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
to proceed your network capture files to generate the JSON files:

    ./potiron-json-ipsumpdump.py -k -r /tmp/test-honeypot-1-20140826000000.cap.gz -d ../out/
    potiron[24989]: [INFO] Created filename ../out/2014/08/26/test-honeypot-1-20140826000000.json

Then the JSON file can be imported into the Redis database:

    ./potiron-redis.py --filename ../out/2014/08/26/test-honeypot-1-20140826000000.json --unix /tmp/redis.sock

