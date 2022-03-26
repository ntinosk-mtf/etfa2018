#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 This is distributed under GNU LGPL license, 
 Source code for Modbus//TCP fuzzer used for the ETFA 2015//2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr
 This is distributed under GNU LGPL license, see license.txt

"""

import logging
import logging.handlers as handlers

ProductName ='MTF-Storm'
Test SUT = 'Modbus TCP slave '
VERSION = '1.0'
Url = 'https://github.com/ntinosk-mtf/etfa2018'

# create logger
logger = modbus_tk.utils.create_logger("console")
lgr=logging.getLogger('')
