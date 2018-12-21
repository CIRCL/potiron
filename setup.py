#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from setuptools import setup

setup(
    name='potiron',
    authors=['Gérard Wagener', 'Christian Studer'],
    author_emails=['gerard.wagener@circl.lu', 'christian.studer@circl.lu'],
    maintainer='Christian Studer',
    url='https://github.com/CIRCL/potiron',
    description='Potiron - Normalize, Index and Visualize Network Capture.',
    packages=['potiron'],
    scripts=['bin/run_redis.py', 'bin/parse_pcap_files.py'],
    classifiers=[
        'License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)',
        'Environment :: Console',
        'Operating System :: POSIX :: Linux',
        'Intended Audience :: Science/Research',
        'Intended Audience :: Telecommunications Industry',
        'Intended Audience :: Information Technology',
        'Programming Language :: Python :: 3',
        'Topic :: Security',
        'Topic :: Internet'
    ]
)
