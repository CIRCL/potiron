
potiron
=======

potiron -  Normalize, Index, Enrich and Visualize Network Capture

potiron is a tool to analyze a series of network capture (pcap) files, parse these with standard tools and normalize
it in JSON format. Then the JSON format is imported into a Redis database to visualize the
normalized information.

The current version potiron currently supports ipsumdump.

Requirements
------------

* Python 2.7
* Flask
* Redis
* ipsumdump

