#!/usr/bin/python
# Script to generate the translation of the keys to human readable
# stuff
# TODO add a gui in the settings for describing the fields
import redis
import sys
version = "1.0"
# TODO error handling when no redis socket is specified
usock = sys.argv[1]
red = redis.Redis(unix_socket_path=usock)
# Set translation names
red.hset("TR:sipcity", "", "Unknown")
red.hset("TR:protocol", 6, "TCP")
red.hset("TR:protocol", 17, "UDP")
red.hset("TR:protocol", 1, "ICMP")
red.hset("TR:protocol", 41, "IPv6")
red.hset("TR:icmptype", 0, "Echo Reply")
red.hset("TR:icmptype", 3, "Destination Unreachable")
red.hset("TR:icmptype", 5, "Redirect")
red.hset("TR:icmptype", 8, "Echo")
red.hset("TR:icmptype", 11, "Time Exceeded")
red.hset("TR:icmptype", 13, "Timestamp")
# TODO filter these codes out
red.hset("TR:icmptype", "-", "Not set")
red.hset("TR:dport", -1, "Not set")
red.hset("TR:sport", -1, "Not set")
red.hset("TR:ipop", ".", "Not set")
# Translate the reverse fields
red.hset("RT:sipcity", "Unknown", "")
red.hset("RT:protocol", "TCP", 6)
red.hset("RT:protocol", "UDP", 17)
red.hset("RT:protocol", "ICMP", 1)
red.hset("RT:protocol", "IPv6", 41)
red.hset("RT:icmptype", "Echo Reply", 0)
red.hset("RT:icmptype", "Destination Unreachable", 3)
red.hset("RT:icmptype", "Redirect", 5)
red.hset("RT:icmptype", "Echo", 8)
red.hset("RT:icmptype", "Time Exceeded", 11)
red.hset("RT:icmptype", "Timestamp", 13)
# TODO filter these codes out
red.hset("RT:icmptype", "Not set", "-")
red.hset("RT:dport", "Not set", -1)
red.hset("RT:sport", "Not set", -1)
red.hset("RT:ipop", "Not set", ".")
# Translate the reverse fields


# Describe fields
red.set("DS:sipcity", "sipcity is the city related to the source IP address that probed the sensor.")
red.set("DS:protocol", "protocol is the protocol field set in the IP packet.")
red.set("DS:iptos", "iptos is the type of service (TOS) field in the IP packet.")
red.set("DS:ipttl", "ipttl is the Time To Live (TTL) field in the IP packet.")
red.set("DS:ipsrc", "ipsrc is the source IP address that probed the sensor.")
red.set("DS:icmptype", "icmptype is the ICMP Type field set in the IP packet.")
red.set("DS:length", "length is the length of the IP packet.")
red.set("DS:dport", "dport is the destination port of an UDP or TCP packet.")
red.set("DS:sipcountry", "sipcounty is the country related to the source IP address that probed the sensor.")
red.set("DS:sport", "sport is the source port of the UDP or TCP packet.")
red.set("DS:icmpcode", "icmpcode is the ICMP code found in an ICMP packet.")
red.set("DS:ipop", "ipop are options of the IP packet.")
