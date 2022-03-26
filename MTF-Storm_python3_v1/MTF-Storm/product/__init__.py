#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 This is distributed under GNU LGPL license, 
 Source code for Modbus//TCP fuzzer used for the ETFA 2015//2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr
 This is distributed under GNU LGPL license, see license.txt

 product library from pymodbus v2.1.x 
 product TestQueries TestQueriesSerialFC 

"""
from  .testQueries import TestQueries as TestQueries
from  .testQueriesSerialFC import TestQueriesSerialFC as TestQueriesSerialFC
from  .message import *
from .serial_message import *
from .diag import *  #problem 


