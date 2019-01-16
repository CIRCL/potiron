#!/usr/bin/env python3
# -*- coding: utf-8 -*-

from pathlib import Path
from potiron.potiron import check_program, create_dir
from potiron.potiron_parameters import fetch_parameters
from potiron.potiron_tshark import process_files
import argparse
import datetime
import os
import redis
import subprocess
import sys


def define_tshark_filter(tsharkfilter):
    to_return = tsharkfilter[0] if len(tsharkfilter) == 0 else " && ".join(tsharkfilter)
    return to_return


def fetch_files(directory: Path):
    to_return = []
    for dir_ in directory.iterdir():
        if dir_.is_file():
            if any([dir_.name.endswith('cap'), dir_.name.endswith('cap.gz')]):
                to_return.append(str(dir_))
        else:
            to_return.extend(fetch_files(dir_))
    return to_return


if __name__ == '__main__':
    # If tshark is not installed, exit and raise the error
    if not check_program('tshark'):
        raise OSError("The program tshark is not installed")
    # FIXME Put in config file

    # Parameters parser
    parser = argparse.ArgumentParser(description="Start the tool tshark and transform the output in a json document")
    parser.add_argument("-i", "--input", type=str, nargs=1, required=True, help="Pcap or compressed pcap filename")
    parser.add_argument("-c", "--console", action='store_true', help="Log output also to console")
    parser.add_argument("-ff", "--fieldfilter", nargs='+',help='Parameters to filter fields to display (ex: "tcp.srcport udp.srcport")')
    parser.add_argument("-o", "--outputdir", type=str, nargs=1, help="Output directory where the json documents will be stored")
    parser.add_argument("-tf", "--tsharkfilter", type=str, nargs='+', help='Tshark Filter (with wireshark/tshark synthax. ex: "ip.proto == 6")')
    parser.add_argument('-u','--unix', type=str, nargs=1, required=True, help='Unix socket to connect to redis-server')
    parser.add_argument('-ck', '--combined_keys', action='store_true', help='Set if combined keys should be used')
    parser.add_argument('-ej', '--enable_json', action='store_true', help='Enable storage into json files')
    args = parser.parse_args()
    logconsole = args.console
    usocket = args.unix[0]
    try:
        red = redis.Redis(unix_socket_path=usocket)
    except redis.ConnectionError as e:
        sys.exit("Could not connect to redis. {}".format(e))
    if os.path.exists(args.input[0]) is False:
        sys.stderr.write("The filename {} was not found\n".format(args.input[0]))
        sys.exit(1)
    input_directory = Path(args.input[0])
    files = fetch_files(input_directory)

    if args.fieldfilter is None:
        args.fieldfilter = []

    tsharkfilter = define_tshark_filter(args.tsharkfilter) if args.tsharkfilter is not None else ""

    enable_json = args.enable_json

    if not enable_json:
        rootdir = 'None'
    else:
        if args.outputdir is None:
            sys.stderr.write("You should specify an output directory.\n")
            sys.exit(1)
        rootdir = args.outputdir[0]
        create_dir(rootdir)
        if os.path.isdir(rootdir) is False:
            sys.stderr.write("The root directory is not a directory\n")
            sys.exit(1)

    ck = args.combined_keys

    args = {'rootdir': rootdir, 'field_filter': args.fieldfilter, 'ck': str(ck), 'tshark_filter': tsharkfilter,
            'enable_json': str(enable_json), 'red': red, 'logconsole': str(logconsole)}
    fetch_parameters(**args)
    process_files(red, files)
