#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 This is distributed under GNU LGPL license, 
 Source code for Modbus//TCP fuzzer used for the ETFA 2015//2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr
 This is distributed under GNU LGPL license, see license.txt

"""
"""
from . basetest import test_MBAP 
from . basetest import test_format 
from . basetest import test_field_PDU
from . basetest import reconnaissance
from . basetest import valid_request 
"""

from  .test_MBAP import *
from  .test_format import test_illegal_PDU 
from .test_field_PDU import fuzzer_pdu
from  .valid_request import  fuzzer_None 
from  .reconnaissance  import black_box,black_box_pcap 


