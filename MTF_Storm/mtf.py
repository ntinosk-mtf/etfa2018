#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
 This is distributed under GNU LGPL license, 
 Source code for Modbus/TCP fuzzer used for the ETFA 2015/2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr
 Use Modbus TestKit: Implementation of Modbus protocol in python
 The modbus_tk simulator is a console application which is running a server with TCP  

"""
import getopt
import traceback
import math
import sys
import operator
from time import *
import logging.handlers as handlers
from datetime import datetime
import os
import signal
from random import *
import decimal
import modbus_tk
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
import modbus_tk.hooks as hooks
from itertools import izip_longest
from itertools import count 
import itertools
from itertools import chain
from math import ceil
from hashlib import sha256
import csv
import scapy.layers.l2
import scapy.layers.inet
from scapy.error import Scapy_Exception
from scapy.all import *
import fuzz_session
from modlib import *
from struct import *
import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
from utils_b import *
import functools
import operator
import metacomm.combinatorics.all_pairs2
#Numpy provides a large set of numeric datatypes that you can use to construct arrays.
#Numpy tries to guess a datatype when you create an array,
import numpy as np

#library from pymodbus 1.2.0 
from message import *
from serial_message import *
from diag import *

#library from sulley
from  s_primitives import *
#The RotatingFileHandler 
from logging.handlers import RotatingFileHandler
from coloredlogs import ColoredFormatter
#define  function, exeption e.a
from defines import *
from add_method  import *
from dict_operation_f_test  import *

from collections import OrderedDict

#--------------------------------------------------------------------------------------------------------------------#
#Modbus tcp /basic :
#Modbus TCP PDU includes the 
#Modbus application protocol (MBAP) in addition to the Modbus application PDU used in the serial protocol
#The MBAP header has four fields: (i) transaction identifier, (ii) protocol identifier, (iii) length, 
#and (iv) unit identifier. The transaction identifier permits devices to pair matching requests
#and replies on a communication channel.
#The protocol identifier indicates the application protocol encapsulated by the MBAP header (zero for Modbus).
#Since application PDUs have a maximum size of 253 bytes and the length of the MBAP is fixed at seven bytes, 
#the maximum size of a Modbus TCP data unit is 260 bytes. 

#Modbus function codes specify :
#Valid public codes fall in the non­contiguous ranges:  1, 64 , 73, 99  and 111,127.
#User-defined codes in the [65, 72] and [100, 110] ranges are not considered in the Modbus standard;
#their implementations are left to vendors. 
#Reserved function codes are public codes that may be used to ensure compatibility with legacy systems. 
#Function code values in the unused range [128, 255] indicate error conditions in response messages.
#The function code for a negative response is computed by adding 128 to the function code of the request message

#------------------------------------------------------------
# Modbus TCP Messages
# ------------------------------------------------------------
# [         MBAP Header         ] [ Function Code] [ Data ]
# [ tid ][ pid ][ length ][ uid ]
#   2b     2b     2b        1b           1b           Nb
#

# Common  Function Codes Modbus 
#   01 (0x01) Read Coils
#   02 (0x02) Read Discrete Inputs
#   03 (0x03) Read Holding Registers
#   04 (0x04) Read Input Registers
#
#   05 (0x05) Write Single Coil
#   06 (0x06) Write Single Holding Register
#
#
#   15 (0x0F) Write Multiple Coils
#   16 (0x10) Write Multiple Holding Registers
#
#   17 (0x11) Report Slave ID (Serial Line only)
#   23 (0x17) Read/Write Multiple Registers   
#   22 (0x16) Mask Write Register
#
#   File record access  
#   24 (0x18) Read FIFO queue    
#   20 (0x14) Read File record  
#   21 (0x15) Write File record 

#      Diagnostics-(Serial Line only)
#   07 (0x07) Read Exception Status 
#   08 (0x08)  Diagnostics  
#   11 (0xOB)  Get Com event counter  
#   12 (0x0C)  Get Com Event Log  
#   17 (0x11)  Report Server  ID
#  
#   43 sub code 14  (0x2B) Read device Identification  
#   43 ( 0x2B) sub code 13/14 Encapsulated Interface Transpor   
#
#-------------Exception Responses-----------

#Function Code in Request   Function Code in Exception Response
#-----------------------------------------------------------------
#  01 (01 hex) 0000 0001       129 (81 hex) 1000 0000
#  02 (02 hex) 0000 0010       130 (82 hex) 1000 0010 
#  03 (03 hex) 0000 0011       131 (83 hex) 1000 0011
#  04 (04 hex) 0000 0100       132 (84 hex) 1000 0100
#  05 (05 hex) 0000 0101       133 (85 hex) 1000 0101
#  06 (06 hex) 0000 0110       134 (86 hex) 1000 0110
#  15 (0F hex) 0000 1111       143 (8F hex) 1000 1111
#  16 (10 hex) 0001 0000       144 (90 hex) 1001 0000

#------------MODBUS Exception Codes ---------

# (01 hex) ILLEGAL FUNCTION
# (02 hex) ILLEGAL DATA ADDRESS
# (03 hex) ILLEGAL DATA VALUE
# (04 hex) SERVER  DEVICE FAILURE
# (05 hex) ACKNOWLEDGE
# (06 hex) SERVER  DEVICE BUSY
# (08 hex) MEMORY PARITY ERROR
# (0A hex) GATEWAY PATH UNAVAILABLE
# (0B hex) GATEWAY TARGET DEVICE 
#          FAILED TO RESPOND


#** Protocol modbus specification 
#----READ_COILS/ READ_DISCRETE_INPUTS

#Function code      1 Byte    0x01/0x02
#Starting Address   2 Bytes   0x0000 to 0xFFFF
#Quantity of coils  2 Bytes   1 to 2000 (0x7D0)

#-----READ_HOLDING_REGISTERS/READ_INPUT_REGISTERS 
#Function code          1   Byte    0x03/0x04
#Starting Address       2   Bytes   0x0000 to 0xFFFF
#Quantity of Registers  2   Bytes   1 to 125 (0x7D)

#------------Write Multiple Coils ---------------------
#Function code          1 Byte    0x0F
#Starting Address       2 Bytes   0x0000 to 0xFFFF
#Quantity of Outputs    2 Bytes   0x0001 to 0x07B0 (1968 dec)
#Byte Count             1 Byte    N*

#---Write Multiple registers 
#Function code          1 Byte  0x10
#Quantity of Registers  2 Bytes  0x0001 to 0x007B (123 dec)
#Byte Count             1 Byte  2 x N*
#Registers Value        N* x 2 Bytes   value
#*N  = Quantity of Registers

#-----------------  example use --------------------------------------------------------#
# pdu sruct.pack for fc support mobdus_tk
#--READ_COILS,READ_DISCRETE_INPUTS,READ_HOLDING_REGISTERS,READ_INPUT_REGISTERS 
#pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)-

#--(WRITE_SINGLE_COIL,WRITE_SINGLE_REGISTER)
#pdu = struct.pack(">BHH", function_code, starting_address, output_value)-

#----(WRITE_MULTIPLE_REGISTERS,WRITE_MULTIPLE_COILS)
#pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count) 
#------------------------------------------------------------------------------------------#

#------------------------------ defines import --------------------------------------- #
"""
'''supported modbus_tk functions (8)'''
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
.....
"........
....
s_address=0
l_address=65535
offset_address=65535                       # step for start
step=32768                                 # step for search memory map
quan_step=1                                # fix step for search map /def chk_list
num_of_search=0
   
#list of supported address  / not response address -
supported_address_coil = []
supported_address_input_reg = []
supported_address_dist_input = []
supported_address_hold_reg = []
not_response_address_coil = []
not_response_address_input_reg = []
not_response_address_dist_input = []
not_response_address_hold_reg = []

........
.....
#Define value for MIN MAX Address of bank 
MIN_COILS=0
MAX_COILS=0
MIN_IN_REG=0
....
#define for function 20,21,22, 
Each file contains 10000 records, addressed 0000 to 9999
 
start_address_reco=0
last_address_reco=9999                           
offset_fuzzer_reco=128 
mem_step_reco=64 
"""

"""
#cross product pairs of COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
integer_boundaries for byte count REG: quantity_of_x_list) use  in test_dumplicate_ADU and test fiels PDU 
directly initialize , numpy table 
x= np.array([], dtype=np.init)

pairwice_MBAP=np.array([], dtype=np.int16)
pairwice_READ_COILS=np.array([], dtype=np.int16)
pairwice_READ_DISCRETE_INPUTS=np.array([], dtype=np.int16)
pairwice_READ_HOLDING_REGISTERS=np.array([], dtype=np.int16)
pairwice_READ_INPUT_REGISTERS=np.array([], dtype=np.int16)
......
"""
#-------------------------------------------------end define --------------------------------------------------
#list operation fuzz testing 
#test of single fields, Combinatorial 2-way field MBAP and PDU """
#test_field_MBAP=['transId', 'protoId', 'len','unitId','Combinatorial']
#..........


#This class about  dictionary of  list operation fuzz testing--from dict_operation_f_test  import *
#-----------------------------------------------------------------------------------
"""
class dict_fuzz_object(object):
    
    def __init__(self):
               

        self.Dict_fuzz_operation = {

            'test_field_MBAP':['transId', 'protoId', 'len','unitId','Combinatorial'],
            'test_field_read_fc':['address', 'quantity_of_x', '2-way'] ,
            .......            
           
        }  

    #return dictionary
    def dict_operation(self): return self.Dict_fuzz_operation        
        
    #return key value
    def dict_operation_key(self,key):        
        return self.Dict_fuzz_operation.get(key)

    def int_fuzz_operation(self):                
            fuzz_session.test_field_MBAP= self.dict_operation_key('test_field_MBAP') #ok
            fuzz_session.test_field_read_fc= self.dict_operation_key('test_field_read_fc')#ok
            fuzz_session.test_field_write_fc=self.dict_operation_key('test_field_write_fc')#ok   
            fuzz_session.test_field_mult_fc=self.dict_operation_key('test_field_mult_fc')#ok
            fuzz_session.test_FC_23=self.dict_operation_key('test_FC_23')#ok
            fuzz_session.test_wr_mask_param=self.dict_operation_key('test_wr_mask_param')#ok
            fuzz_session.test_FC43=self.dict_operation_key('test_FC43')#ok
            fuzz_session.Diagnostics_FC_param=self.dict_operation_key('Diagnostics_FC_param')#ok
            fuzz_session.test_field_Read_File_record=self.dict_operation_key('test_field_Read_File_record')#ok
            fuzz_session.test_field_Write_File_record=self.dict_operation_key('test_field_Write_File_record')#ok
            fuzz_session.fp=self.dict_operation_key("fp") #ok
            fuzz_session.attack_byte_PDU=self.dict_operation_key('attack_byte_PDU')#ok
"""


"""            
request = (
               
                (0x01, '\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, '\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, '\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, '\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07'),                                       # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b'),                                       # get comm event counters
                (0x0c, '\x0c'),                                       # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02\x04\0xff\xff'),          # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' \
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x00'),                           # read device identification                       # read device identification
        )
response = (
                (0x01, '\x01\x01\x01'),                               # read coils
                (0x02, '\x02\x01\x01'),                               # read discrete inputs
                (0x03, '\x03\x02\x01\x01'),                           # read holding registers
                (0x04, '\x04\x02\x01\x01'),                           # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07\x00'),                                   # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, '\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, '\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' 
                       '\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, '\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )

bad = (                                                        #ITEM 12  
        (0x80, '\x80\x00\x00\x00'),                            # Unknown Function
        (0x81, '\x81\x00\x00\x00'),                            # error message
        (0x90, '\x90\x00\x00\x00'),
        (0x91, '\x91\x00\x00\x00'),
        (0x92, '\x92\x00\x00\x00'),
        (0x93, '\x93\x00\x00\x00'),
        (0x94, '\x94\x00\x00\x00'),
        (0x95, '\x95\x00\x00\x00'),
        (0x96, '\x96\x00\x00\x00'),
        (0x97, '\x97\x00\x00\x00'),
        (0x98, '\x98\x00\x00\x00'),
        (0x99, '\x99\x00\x00\x00'),                           
      )

exception = (
        (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
        (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
        (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
        (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception
        (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
        (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
        (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
        (0x88, '\x88\x0a\x16\x06'),                           # gateway path unavailable exception
        (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception
      )


diagnostics = (
        
        (00, '\x08\x00\x00\x00\x00'),
        (01, '\x08\x00\x01\x00\x00'),                               #restartCommunaications
        (02, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (03, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (04, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (05, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (06, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (07, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, '\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, '\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, '\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, '\x08\x00\x0f\x00\x00'),                               #ReturnSlaveNoReponseCountResponse
        (14, '\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse
        (15, '\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, '\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, '\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse
        (18, '\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse
        (19, '\x08\x00\x15' + '\x00\x00' * 55),                     #etClearModbusPlusResponse
        (20, '\x08\x00\x01\x00\xff')                                #restartCommunaications
      )

little_endian_payload = (
                       (1, '\x01\x02\x00\x03\x00\x00\x00\x04\x00\x00\x00\x00'), 
                       (2, '\x00\x00\x00\xff\xfe\xff\xfd\xff\xff\xff\xfc\xff'),
                       (3, '\xff\xff\xff\xff\xff\xff\x00\x00\xa0\x3f\x00\x00'),
                       (4, '\x00\x00\x00\x00\x19\x40\x74\x65\x73\x74\x11'),
                       )
"""                       
#------------------------------------------------------------------------------------------------------
# This class about global variable mode search and fuzzing not use  /Use module fuzz_session.py, defines.py
#-----------------------------------------------------------------------------------------------------
class Fuzz_session:
  fuzz = None
  
#-------------------------------------------------------------------------------------------------------
# Global variables
#--------------------------------------------------------------------------------------------------------
# Test_suite_list     - assigns a test of  different Suite  fuzz categories
# test_suites_list = [('test_MBAP', 1.0), ('test_message_PDU', 2.0), ('test_field_PDU', 3.0),('Not_fuzz',4.0)]
             
# fuzz_session   - keeps information about the current  session  fuzzer
# ip             - the IP of the machine
# host           - the IP of the remote machine (under test)
# log_file       - stores fuzzing information
# iface          - the interface of the local machine (e.g. eth0)
# search_mode     - bool ,speci are black_box or fuzzer (modbus_b.py , line 221 ..)
# running         - is the fuzzer running?
# csvFile         - stores search information
# pcap_file       - trace pcap file 
# filtered_pcap    --trace pcap file request/response modbus
# mod_file_response -trace pcap file /response modbus
# mod_file_request  -trace pcap file request/modbus

"""
  logs all output to a file, if no file is
  specified, it prints to standard output

"""
 # log to the console
 #console_handler = logging.StreamHandler()
 #level = logging.INFO
 #console_handler.setLevel(level)
 #logger.addHandler(console_handler)
 #create console handler and set level to debug
 #ch = logging.StreamHandler()
 #ch.setLevel(logging.INFO)
 #------------------------------------------------------------

class MyFilter(object):
    """
    apply the filter to each of the two handlers
    """
    def __init__(self, level):
        self.level = level

    def filter(self, logRecord):
        return logRecord.levelno != self.level


class SizedTimedRotatingFileHandler(handlers.TimedRotatingFileHandler):
    """
    Handler for logging to a set of files, which switches from one file
    to the next when the current file reaches a certain size, or at certain
    timed intervals
    If rotation/rollover is wanted, it doesn't make sense to use another
    mode. If for example 'w' were specified, then if there were multiple
    runs of the calling application, the logs from previous runs would be
    lost if the 'w' is respected, because the log file would be truncated
    on each run.
    """
    def __init__(self, filename, mode='a', maxBytes=0, backupCount=0, encoding=None,
                 delay=0, when='h', interval=1, utc=False):
        
        if maxBytes > 0:
            mode = 'a'
        handlers.TimedRotatingFileHandler.__init__(
            self, filename, when, interval, backupCount, encoding, delay, utc)
        self.maxBytes = maxBytes

    def shouldRollover(self, record):
        """
        Determine if rollover should occur.
        Basically, see if the supplied record would cause the file to exceed
        the size limit we have.
        """
        if self.stream is None:                   # delay was set...
            self.stream = self._open()
        if self.maxBytes > 0:                     # are we rolling over?
            msg = "%s\n" % self.format(record)
            self.stream.seek(0, 2)                #due to non-posix-compliant Windows feature
            if self.stream.tell() + len(msg) >= self.maxBytes:
                return 1
        t = int(time.time())
        if t >= self.rolloverAt:
            return 1
        return 0

#-----------------------------------------------------------------------------#
# create logger- -disable log file as >>lgr.disabled = True 
#-----------------------------------------------------------------------------# 
logger = modbus_tk.utils.create_logger("console")
lgr=logging.getLogger('')

#-----------------------------------------------------------------------------#
def log_info(lgr,logger,minLevel=logging.INFO,dir=log_dir) :
    ''' 
    add a rotating handler and compression
    add a file handler/two separation file, 100mb / change
    add filter exeption logging.INFO from  debug log 
    You can specify particular values of maxBytes and backupCount to allow the file to rollover at a predetermined size.
    If backupCount is > 0, when rollover is done, no more than backupCount files are kept - the oldest ones are deleted.
    set up logging to file
    DEBUG
    INFO
    WARNING
    ERROR
    FATAL/CRITICAL/EXCEPTION 
    create a directory if it does not exist log_dir=./log
    Set up logging to the console-it prints to standard output
    The coloredlogs package enables colored terminal output for Python’s logging module.  
    '''          
   
    global filename1,filename2,log_dir
    # Define the default logging message formats.
    file_msg_format = '%(asctime)s %(levelname)-8s: %(message)s'
    console_msg_format = '%(levelname)s: %(message)s'
    
    # Validate the given directory.
    dir = os.path.normpath(dir )
   
    # Create a folder for the logfiles.
    if not os.path.exists(dir):
        os.makedirs(dir)

    lgr.setLevel(logging.INFO)    
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename1 = os.path.join(log_dir, 'info_%s.log' % now)
    filename2 = os.path.join(log_dir, 'error_%s.log' % now)
    
    fh=SizedTimedRotatingFileHandler(
    filename1, maxBytes=200*1000000, backupCount=200,                   
        when='s',interval=1000000,
        )
    #rotating handler maxBytes=  100 mb  
    fh1=SizedTimedRotatingFileHandler(                            
    filename2, maxBytes=100*1000000, backupCount=200,                      
        when='s',interval=10000000,        
        )

    fh1 = logging.FileHandler(filename2)
    fh.setLevel(logging.INFO)
    fh1.setLevel(logging.WARN)
    
    # create a formatter and set the formatter for the handler.
    frmt = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(frmt); fh1.setFormatter(frmt)
    # add the Handler to the logger
    lgr.addHandler(fh);logger.addHandler(fh)
    lgr.addHandler(fh1);logger.addHandler(fh1)
    #Set up logging to the console-it prints to standard output-coloredlogs package enables   
    console_handler = logging.StreamHandler()   
    console_handler.setLevel(minLevel)
    stream_formatter = ColoredFormatter(file_msg_format)
    console_handler.setFormatter(stream_formatter)    
    ch = logging.StreamHandler();lgr.addHandler(console_handler)
#------------------------------------------------------------
# This function print info time duration and total request
#------------------------------------------------------------

def info(start_time,num_of_request):
    
    end_time = datetime.now()
    lgr.info('Duration: {}'.format(end_time - start_time))
    lgr.info('Total request : %d', fuzz_session.num_of_request) 
    
#------------------------------------------------------------
# This function cleans temporary files and stop the fuzzer 
# upon Ctrl+c event
#------------------------------------------------------------
def signal_handler(signal, frame):
   lgr.info('Stopping  Ctrl+c ')
   info(start_time,num_of_request)       # info time and request
   master1.close();sys.exit(0)
#------------------------------------------------------------
# This function cleans temporary log files,coverage, 
# /tmp * save csv file for FC 1-4
# log_dir = "./log/"
#------------------------------------------------------------
def Cleaning_up():   
   
   lgr.info('Cleaning up  log files and ./tmp')
   os.system('sudo rm -rf ' + log_dir + '*.log.*')
   os.system('sudo rm -rf ' + log_dir + '*.log')
   os.system('sudo rm -rf ' + './tmp' + '/*.csv')
    
   """
#-------------------------------------------------------------------------------
#HexByteConversion
#Convert a byte string to it's hex representation for output or visa versa.
#ByteToHex converts byte string "\xFF\xFE\x00\x01" to the string "FF FE 00 01"
#HexToByte converts string "FF FE 00 01" to the byte string "\xFF\xFE\x00\x01"
# test data - different formats but equivalent data
#__hexStr1  = "FFFFFF5F8121070C0000FFFFFFFF5F8129010B"
#__hexStr2  = "FF FF FF 5F 81 21 07 0C 00 00 FF FF FF FF 5F 81 29 01 0B"
#__byteStr = "\xFF\xFF\xFF\x5F\x81\x21\x07\x0C\x00\x00\xFF\xFF\xFF\xFF\x5F\x81\x29\x01\x0B"
    
#-------------------------------------------------------------------------------
def ByteToHex( byteStr ):
    
    #Convert a byte string to it's hex string representation e.g. for output.
    
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()        

    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    #return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )                                #not space

#-------------------------------------------------------------------------------

def HexToByte( hexStr ):
    
    #Convert a string hex byte values into a byte string. The Hex Byte values may
    #or may not be space separated.
    
    # The list comprehension implementation is fractionally slower in this case    
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )
 
    bytes = []

    hexStr = ''.join( hexStr.split(" ") )

    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )
    """
#-----------------------------------------------------------------------------------------------------------------  
# This class fuzz testing  a field of PDU Modbus protocol
# PAIRWISE  test for FC 01 ,02 ,03 ,04 , address +quantity bount + 20   
# program to find all  pairs in both arrays whose  sum is equal to given value x 
    
# cross  pairs parameter of FC to find all  pairs in both arrays whose 
# sum is equal to given value x nd y
# Create a 2D Numpy Array like Matrix
# electing random rows from a NumPy array results in a new array with a specified number of rows from the original.
# All rows are equally likely to be selected. For example, randomly selecting 2 rows from [[a, a, a], [b, b, b],..., 
# Use numpy.random.choice(a, size=k, replace=False) 
# to generate a list of k random indices without repetition from a NumPy array with a rows. 
 
# number_of_rows = an_array.shape[0]
# random_indices = np.random.choice(number_of_rows, size=2, replace=False
# random_rows = an_array[random_indices, :]
#----------------------------------------------------------------------------------------------------------------------
class pairs_address_qua(object):    
       
    def __init__(self ):
        """
        Constructor. Set the Initializing settings
        dir="tmp/" def save dir
           
         """ 

    def pair(self,function_code,l1,l2,maxaddress,minaddress,dir="./tmp"):
        """ 
        PAIRWISE test -create for FC01-FC04.. dir="tmp/" def save dir .csv file fot test
        """        
        dir = os.path.normpath(dir)
        # Create a folder for the logfiles.
        if not os.path.exists(dir):os.makedirs(dir)
        lgr.info("---------------------------    Set PAIRWISE test Initializes from CSV for address vs quantity   ----------------------")
        try:
        
            if os.path.exists(dir+"/FC0%d_pair.csv"%function_code):
                # read CSV file & load into list               
                with open(dir+"/FC0%d_pair.csv"%function_code,'r') as f:
                    reader = csv.reader(f); pairwise_temp = list(reader)                   
                    #convert all elements to Init
                    pairwise = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                    
            else:
                    lgr.warn("not file CSV.......")                  
                    pairwise=self.findPairs(l1, l2, maxaddress,minaddress)
                    with open(dir+"/FC0%d_pair.csv"%function_code,"w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table ..")
                        wr.writerows(pairwise)                                                                                                      
                        #multiple statements on the same line            
        except IOError :lgr.exception("");  pairwise=[]
               
        if len(pairwise)==0:
                raise ValueError ('no data')    
        
        lgr.info('Test case Initializing for FC0%d --------- : %d '% (function_code,np.size(pairwise, 0)))        
        return np.array(pairwise)


    def findPairs(self,list1, list2, max_address,min_address):
        """
        Create a 2D Numpy Array like Matrix
        Write a NumPy program to add a new row to an empty numpy array.
        arr = np.empty((0,3), int)
        arr = np.append(arr, np.array([[10,20,30]]), axis=0)
        arr = np.append(arr, np.array([[40,50,60]]), axis=0)

        Restrictions
        list1[i] + list2[j]) <max_address+512 
        list1[i]<max_address
        Selecting random rows of matrix1 (all invalid),def=number_of_rows, from pair in in_lis
        in_lis=[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                       0xFFFF+2]

        Sample Output:
        [[10 20 30]
        [40 50 60]]
        """ 
        in_lis=[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                       0xFFFF+2] 
        n = len(list1) 
        m = len(list2)            
        # empty numpy array.
        matrixArr1=np.empty((0,2), int)
        matrixArr=np.empty((0,2), int)

        for i in range(0, n): 
            for j in range(0, m): 
                if list1[i]<max_address :
                    if (max_address-256 <(list1[i] + list2[j]) <max_address+256) or  (min_address-256 <(list1[i] + list2[j]) <min_address+256):
                        matrixArr = np.append(matrixArr,[[list1[i],list2[j]]],axis = 0)
                else :
                    if  list1[i] in in_lis :
                        if list2[j] in in_lis :
                            matrixArr1 = np.append(matrixArr1,[[list1[i],list2[j]]],axis = 0)

        numOfColumns = np.size(matrixArr, 1)
        numOfRows = np.size(matrixArr, 0)
        lgr.info('Number of Rows matrixArr  in range memory -+256): %d ', numOfRows)
        numOfRows1 = np.size(matrixArr1, 0)
        lgr.info('Number of Rows matrixArr1 > max_address+256: %d', numOfRows1)

        #Selecting random rows of matrix1 (all invalid),def=number_of_rows
        number_of_rows = matrixArr1.shape[0]
        size=int((number_of_rows*0.25))
        if size >100: size=100
            
        random_indices = np.random.choice(number_of_rows, size, replace=False)
        random_rows = matrixArr1[random_indices, :]
        #append a NumPy array to a NumPy array
        lgr.info ('Matrix3 array append random_indices :%d',size)
        matrix3=np.concatenate((matrixArr, random_rows))
        rowmatrix3 = np.size(matrix3, 0)
        lgr.info('Number of Rows : %d ', rowmatrix3)
        return matrix3

#---------------------------------------------------------------------------------------------------------#
# library for static fuzz VALUE 
# The class  implements integer fuzz heuristics  library of static fuzz VALUE
# Add the supplied integer and border cases to the integer fuzz heuristics library
# negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
# lib_word_binary.extend(bit_field(0, 16, 255, "<","ascii", True).fuzz_library)                       
# lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library      
# lib_dword_binary.extend(bit_field(214748364, 32, 2147483648, "<","ascii", True).fuzz_library)
   
# self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
# only smart values  bound +-1
# self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
# self.library only smart values  bound +-5
    
# add the library num rang 1000 and bound (+-20) 
# for i in xrange(0, self.max_num,1000):
#     self.add_integer_bound(i,self.library)
        
# build the fuzz library num rang 1000 not  bound (+-20)
#    for i in xrange(0, self.max_num,1000):
#      self.library.append(i)
#self.interesting_strings=
#---------------------------------------------------------------------------------------------------------#
class list_of_fuzz(object):
    '''
    
    '''
    def __init__ (self,max_num=None,library=None):
        self.interesting_hex=[];self.max_num = 65535
        self.illegal_pdu_len=[];self.bound=[]
        if library is None:self.library = []            
        self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library   
        self.lib_word_binary=bit_field(0, 16, -32768, "<","ascii", signed=True,fuzzable=True).fuzz_library
        self.simple_lib_word_binary=bit_field_simple(0, 16, 65535, "<","ascii", signed=True,fuzzable=True).fuzz_library
        #for all list min/max address
        self.MIN_COILS=fuzz_session.MIN_COILS
        self.MAX_COILS=fuzz_session.MAX_COILS
        self.MIN_IN_REG=fuzz_session.MIN_IN_REG
        self.MAX_IN_REG=fuzz_session.MAX_IN_REG
        self.MIN_DIS_IN=fuzz_session.MIN_DIS_IN
        self.MAX_DIS_IN=fuzz_session.MAX_DIS_IN
        self.MIN_HO_REG=fuzz_session.MIN_HO_REG
        self.MAX_HO_REG=fuzz_session.MAX_HO_REG

        self.address_list_bound_COILS=[self.MIN_COILS,self.MAX_COILS]
        self.address_list_bound_DIS_IN=[self.MIN_DIS_IN,self.MAX_DIS_IN]
        self.address_list_bound_IN_REG=[self.MIN_IN_REG,self.MAX_IN_REG]
        self.address_list_bound_HO_REG=[self.MIN_HO_REG,self.MAX_HO_REG]

    def add_integer_bound(self, integer,library,b):
        '''
        Add the supplied integer and border cases to the integer fuzz heuristics library.
        @type  integer: Int
        @param integer: Integer to append to fuzz heuristics
        '''

        for i in xrange(-b, +b):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if (0<= case <= self.max_num and self.max_num >0 ) :
                if case not in library:
                    library.append(case)
            elif  (self.max_num <= case <= -self.max_num) :                   
                if case not in library:
                    library(case)          
                 

    def num_of_list (self):
        '''
        Calculate and return the total number of list.
        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''
        return len(self.library)    

    def iter_byte_string_list(self):
        '''
        in defines.py
        fuzz heuristics for test not specified len ADU or PDU,add some interesting  bytestrings
        add extra item in list,some binary strings ,add bad and exception
        for fct,msg  in bad:self.interesting_hex.append(msg)
        for fct,msg  in exception:self.interesting_hex.append(msg)    #dis       
        for fct,msg  in diagnostics:self.interesting_hex.append(msg)
        "\xfe",  "\x00", "\xfe",
        \xde\xad\xbe\xef,
        expands to 4 characters under utf16             
        self.add_long_strings("\x14")
        self.add_long_strings("\xFE")   
        "%\xfe\xf0%\x00\xff",
        "%\xfe\xf0%\x01\xff"
        diagnostics = (
        
        \x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        .........
        bad = (                                                  
        (0x80, '\x80\x00\x00\x00'),                            # Unknown Function
        ....                   
      )

        exception = (
        (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
        (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
        (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
        (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
        (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception
        (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
        (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
        (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
        (0x88, '\x88\x0a\x16\x06'),                           # gateway path unavailable exception
        (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception

        25, '%\xfe\xf0%\x00\xff'),
            (26, '%\xfe\xf0%\x01\xff'),
            (27, '\xde\xad\xbe\xef'),
        ........
      )

        '''
        sequence = (            
            (1, '\x00\x00'), 
            (4, '\x00\x03'),         
            (5, '\xFF'), 
            (7, '\x00\x04'), 
            (8, '\xFE'),     
            (11, '\x00\x06'), 
            (12, '\x00\x05'),   
            (14,'\x89\x0b'), 
            (15, '\x00\xff'),   
            (16, '\x00\xfe'),   
            (20, '\x00\x0b'),  
            (21, '\x00\x0c'),   
            (22, 'x08\x00\x01'),
            (24, '\xFE\xFF'),   
            (25, '%\xfe\xf0%'),
            (27, '\xde\xad'),
            (28,'\x08\x00\x04')
            )
        for fct,msg  in sequence :self.interesting_hex.append(msg)            
        return self.interesting_hex


    def illegal_len_list(self):
        '''
        fuzz heuristics for test not specified len ADU or PDU
        add extra item in list,  e.g tcp frame 1448 +-  ,
        range(243,253,2)) as ADU 243+12 ,(255,265 ) (e.g len FC01 =12B)
        remove all empty strings /dumple item/ sort
        list(filter(lambda x: x!= 0 and  x<=255, self.library)), valid len
        list(filter(lambda x: x!= 0 and  x>=255, self.library)), valid len
        ommon_len_valid=[1, 2, 3, 4, 5,  8,  16,  32, 63, 
         64, 65, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 245, 247, 249, 251, 252, 253, 254, 255]

        '''
        common_len_valid=[1, 2, 3, 4, 5,  8,  16,  32, 63, 64, 65, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 245, 247, 249]
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library.extend(list(range(1480,1520,2)))
        self.library.extend(list(range(243,253,2)))
        self.library=list(filter(lambda x: x<=33000, self.library ))
        self.library.extend([5000, 10000, 20000, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,0xFFFF+2])
        self.library=list(set(self.library))                         #fix for newer ver python
        self.library.sort(reverse=False)
        return list(filter(lambda x: x!= 0 and  x>=250, self.library))+common_len_valid

    #  --NOT USE                               
    def list_pdu_len(self) :
        pdu_len=self.illegal_len_list()                      
        fuzz_session.len_of_list=len(pdu_len)
        return pdu_len
     #-- NOT USE 
    def init_illegal_pdu_list(self):                
        self.illegal_pdu_len=self.illegal_len_list()   
        fuzz_session.illegal_pdu_len= self.illegal_pdu_len
        fuzz_session.len_of_list=len(self.illegal_pdu_len)
        print fuzz_session.len_of_list
        return

    def list_of_address(self,MIN,MAX) :
        """
        add extra item in fuzz library for  min/max address,
        remove all empty strings and dumple item and sort
        build the fuzz library for min/max address bound +-20 (,
        Bitwise-AND, signed 16-bit numbers as -256 ,-512 ,-1024
        self.library common smart value +-5, and value > max  %1000 +-2 
        
        """
        final_list_address=[]; list_address=[];self.bound=[MIN,MAX,MAX/2,MAX/3]
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library        
        for x in self.bound:  
              self.add_integer_bound(x,list_address,22)
        for i in xrange(0, MAX,1000):
             self.add_integer_bound(i,list_address,5)
        for x in list(filter(lambda x:x % 1000==0, xrange(MAX,65535))):  
              self.add_integer_bound(x,list_address,2) 
        for x in list(filter(lambda x:x % 1000==0, xrange(0,MIN))):  
              self.add_integer_bound(x,list_address,2)            
          
        #Bitwise-AND, unsigned 16-bit numbers                                     
        self.lib_word_binary=map(lambda x: x & 0xFFFF, self.lib_word_binary)                      
        final_list_address= list_address+self.library+list (set(self.lib_word_binary))
        final_list_address=list(set(final_list_address)); final_list_address.sort(reverse=False)                                      
        return final_list_address
        
    def list_address_for_cart_prod(self,MIN,MAX,b) :
        """
        cartesian product with a limited number of interests, use fuzzing parameter PDU
        add item in fuzz library for  min/max address,
        build the fuzz library for min/max address,
        Bitwise-AND, "smart" values signed 16-bit numbers as -256 ,-512 ,-1024, ..-16384 and  boundary to self.max_num-16384/48k ram 
        build the fuzz library not boundary,remove all empty strings and dumple item and sort
        if <5 use self.library_simple

        """                   
        final_list_address=[];list_address=[]; self.bound=[MIN,MAX]
        for x in self.bound:  
              self.add_integer_bound(x,list_address,b) 

        if b<5:
            final_list_address=self.library_simple+list_address+[5000,10000,49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535]   
        else:
            if MAX>32768:self.library=list(filter(lambda x: x<=(49152+5), bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library))            
            else :self.library=list(filter(lambda x: x<=(32768+5), bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library))
            final_list_address=self.library+list_address+[5000,10000,49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535]    
                                            
        final_list_address=list(set(final_list_address));final_list_address.sort(reverse=False) 
        return final_list_address   

    def list_of_quantity(self,MIN,MAX) :
        """
        add extra item in fuzz library for quauntity
        remove all empty strings /and dumple item/sort
        build the fuzz library for quauantity (min/max ),
        Bitwise-AND, signed 16-bit numbers -256 ,-512 ,-1024
        bound for quauantity register and coil, 
        self.library common smart value +-5, and value > max  %1000 +-2 
        """
        
        list_qua=[];self.bound=[MIN,MAX,MAX/2, MAX/3] ; self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        for i in xrange(0, MAX,1000):
             self.add_integer_bound(i,list_qua,5)

        for x in list(filter(lambda x:x % 1000==0, xrange(MAX,65535))):  
              self.add_integer_bound(x,list_qua,2)             
        
        for x in self.bound:  
              self.add_integer_bound(x,list_qua,22) 
                                              
        self.lib_word_binary=map(lambda x: x & 0xFFFF, self.lib_word_binary )
        final_list_qua =self.library+list(self.lib_word_binary)+list_qua
        final_list_qua=list(set(final_list_qua));final_list_qua.sort(reverse=False) 
        return final_list_qua
        
    def list_quantity_for_cart_prod(self,MIN,MAX,b) :
        """
        cartesian product with a limited number of interests,  use fuzzing parameter PDU
        add item in fuzz library for quauntity
        build the fuzz library for quauantity (min/max ),
        Bitwise-AND, signed 16-bit numbers -256 ,-512 ,-1024, -16384 , not boundary [5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        bound for quauantity register and coil,
        remove all empty strings /and dumple item/sort
        if b (bountery) <5 use self.library_simple
        """
        final_list_qua=[];list_qua=[];self.bound=[MIN,MAX]    
        for x in self.bound:  
              self.add_integer_bound(x,list_qua,b)

        if b<5:
            self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
            final_list_qua =list_qua+self.library_simple+[5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        else :
             self.library=list(filter(lambda x: x<=(32768+5), bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library))
             final_list_qua =list_qua+self.library+[5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        
        final_list_qua=list(set(final_list_qua));final_list_qua.sort(reverse=False)
        return final_list_qua 
    

    def lib_word(self):   
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
        e.g 32-bit
        lib_word_binary.extend(bit_field(0, 16, 255, "<","ascii", True).fuzz_library)                       
        lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library      
        lib_dword_binary.extend(bit_field(214748364, 32, 2147483648, "<","ascii", True).fuzz_library) 
        """ 
        list_of_boun=[];self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        
        for i in xrange(0, self.max_num,1000):
             self.add_integer_bound(i,list_of_boun,5)
             
        for x in self.library:  
              self.add_integer_bound(x,list_of_boun,22)            
        
        self.lib_word_binary=map(lambda x: x & 0xFFFF, self.lib_word_binary )      
        final_list=self.library+list(self.lib_word_binary)+list_of_boun
        final_list=list(set(final_list));final_list.sort(reverse=False) 
        return  final_list
    
    def lib_word_cart(self):                   
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
        use for cartesian protect such 2-way FC05, FC06
        not bound value  for boundaries simple +-1
        self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library 
        """ 
        list_of_boun=[];self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library 
        self.lib_word_binary=map(lambda x: x & 0xFFFF, self.lib_word_binary )      
        final_list=self.library_simple
        final_list=list(set(final_list))
        final_list.sort(reverse=False)   
        return  final_list

    def lib_byte_test(self,MIN=0,SPEC=0,MAX=65535):   #add  new 18.03.20/and 29.11.20
        """
        limited number, library for 1 byte fields and value use the 2-way test, MIN,MAX, SPECIAL VALUE, +-20 
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library use for 1 byte or 2 byte fields  test  2-way
        for 1 byte fields  single test add MAX/3,MAX/5, and special value +-10
        self.library=60 value
        return sort

        """
        tmp=[]; end=[];list_of_boun=[];self.bound=[MIN,SPEC,MAX,MAX/3,MAX/5] 
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        if MAX==256 :
            for x in self.bound:  
              self.add_integer_bound(x,tmp,8)
            end=tmp+self.library
                       
        else:    
            for x in self.bound:  
                  self.add_integer_bound(x,tmp,22)
            for x in self.library:  
                  self.add_integer_bound(x,list_of_boun,22)
            end=tmp+self.simple_lib_word_binary+list_of_boun              
       
        end=list(set(end));end.sort()
        if MAX==65535 :
            return list(filter(lambda x: x<= 65535, end))
        return list(filter(lambda x: x<= 255, end))
        
    def lib_exhaustive_256(self):
        """
        integer exhaustive fuzz heuristics library (all value), not sort 
        negatve integer build  fuzz library. use for byte_count field in test_field_PDU and unit_id in MBAP
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        list(filter(lambda x:x not in self.library,list(range(0, 256)))), value not interesting and valid
        sort 0,6 only interesting first and other valid next 

        """ 
        return list(filter(lambda x: x<= 255, self.library+list(filter(lambda x:x not in self.library,list(range(0, 256))))))

    def lib_exhaustive_65535(self):
        """
        integer exhaustive fuzz heuristics library
        negatve integer build  fuzz library. use for exhaustive fields 2 BYTE  

        """ 
            
        return list(range(0, 65536))

    def lib_interesting_256(self):
        """
        integer interesting value up to 256  heuristics library
        negatve integer build  fuzz library. use for byte_count, dumplecate ADU,
        field in test_field_PDU and unit_id in MBAP
        case=60  

        """        
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library=list(set(self.library));self.library.sort(reverse=False)               
        return list(filter(lambda x: x<= 255, self.library ))       

    def lib_interesting_256_exte(self):
        """
        integer interesting value up to 256  and extend 512,1024,2048,4096 heuristics library
        negatve integer build  fuzz library Multiple ADU,
          
        """        
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library=list(set(self.library));self.library.sort(reverse=False)      
        return list(filter(lambda x: x<= 256, self.library )) +[512,1024,2048,4096]
        

    def lib_interesting_128_to_255(self):
        """
        integer interesting value  128_to_255 heuristics library
        negatve integer build  fuzz library. use to check FC Exception
        boundary User-defined, public_codes, user_codes [171,191,201,226,227,237,238]

        """
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library.extend(list(range(128,150,1)));self.library=list(set(self.library)) 
        self.library.sort(reverse=False)
        return list(filter(lambda x: 128<= x<= 255, self.library )) + [171,191,201,226,227,237,238]

    def lib_of_MBAP_length(self) :
        """
        list fuzz library for test MBAP length..-to be configured !!not sort with dumplicate MBAP_length.extend(list(range(0,10,1))
        repait bount (260),repait space (0,9)
        remove all empty strings, not sort with dumplicate 
        [666] flag to stop test as last elements
        case=
        len           4        1368        
        """
        final_list_length=[]
        iterest_value=[0,128, 255, 256, 257, 259,260,261, 263,511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8196,10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 65534,65533,65535]
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        MBAP_length=list(range(1450,1550,1)) ;  MBAP_length.extend(list(range(250,270,1)));MBAP_length.extend(list(range(0,10,1))) 
        
        for i in xrange(0, self.max_num,1000):
             self.add_integer_bound(i,MBAP_length,3)
        MBAP_length.extend(list(range(250,270,1))) ;MBAP_length.extend(list(range(0,10,1))); MBAP_length.extend(list(range(2054,32768,64)))
        MBAP_length.extend(list(range(0,10,1))) ;final_list_length.extend(self.library)          
        final_list_length = list(set(self.library))+iterest_value+MBAP_length+iterest_value+[666]       
        return list(filter(lambda x: x<65536, final_list_length))  

    def lib_of_MBAP_transid(self,MIN,MAX) :
        """
        list fuzz library for test trans id, step , reversed ,....
        case=9437(with dumplicate)
        
        """
        MBAP_same_value=[];MBAP_inc_value=[];MBAP_transid=list(range(0,99))
        MBAP_iterest_value=[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8196,10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1,65535]
        MBAP_iterest_value_rev=list(reversed(MBAP_iterest_value))
        
        # build the fuzz library for (min/max)
        MBAP_inc_value=list(range(MIN,MAX,16)) ;  MBAP_inc_value.extend(list(range(MIN,MAX,128)))    
        MBAP_inc_value.extend(list(range(MIN,MAX,2048)));MBAP_rev_value=list(reversed(MBAP_inc_value))    
        return MBAP_iterest_value+MBAP_iterest_value_rev+MBAP_transid+MBAP_inc_value+MBAP_rev_value

    def lib_of_MBAP_protocol(self,MIN,MAX) :
        """
        add extra item in list fuzz library for test MBAP protocol(
        remove all empty strings and dumple item/sort,and valid value
        final_list_prot=list(set(final_list_prot)) ,remove dumplicate
        total of test  MBAP protocol: 942
        """
        final_list_prot=[]; MBAP_protocol=[]
        self.bound=[MIN,MAX];self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        
        # build the fuzz library for (min/max)
        for x in self.bound:  
              self.add_integer_bound(x,MBAP_protocol,20)
        for i in xrange(0, self.max_num,1000):
             self.add_integer_bound(i,MBAP_protocol,5)
        final_list_prot= self.library+MBAP_protocol
        final_list_prot=list(set(final_list_prot))          
        final_list_prot.sort(reverse=False)
        return list(filter(lambda x:x<65536, final_list_prot))                                                       

    def lib_test_sub_diag(self):
        """
        add extra item in list self.library, remove all empty strings /dumple item/ sort
        """
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        diagnostics_library=self.library+list(range(0,21,1)) ;diagnostics_library=list(set(diagnostics_library))                                     
        diagnostics_library.sort(reverse=False)
        return diagnostics_library
        

#--------------------------------------------------------------------------------------------------------------------------#
#library for write results to file *.csv for test single field,write results  Coverage  "{:.1%}".format(0.1234)-> '12.3%'
#--------------------------------------------------------------------------------------------------------------------------#
class test_case_coverage:

    def __init__(self ):        
        """ Constructor. Set the Initializing settings
        """    
    def reset(self):
        #reset counters
        fuzz_session.field1_valid=0
        fuzz_session.field1_invalid=0
        fuzz_session.field2_valid=0
        fuzz_session.field2_invalid=0
        fuzz_session.field3_valid=0
        fuzz_session.field3_invalid=0
        fuzz_session.field4_valid=0
        fuzz_session.field4_invalid=0
        fuzz_session.field5_valid=0
        fuzz_session.field5_invalid=0
        fuzz_session.field6_valid=0
        fuzz_session.field6_invalid=0
        fuzz_session.address_quantity_invalid=0
        fuzz_session.address_quantity_valid=0

    
    def test_case (self,function_code,test_field,test_fields,tmp_test_list,dir="test_tuple"):
        """
        this method write results to file *.csv for test single field '
        tmp_test_list is np array

        """
             
        csvfile=dir+'/test_FC%s_%s.csv' % (function_code,test_field)
        csvfile_bak=dir+'/test_FC%s_%s.bak' % (function_code,test_field)
                
        if not os.path.exists(log_dir+dir):
        	 os.makedirs(log_dir+dir)
        elif os.path.exists(log_dir+csvfile):
            lgr.warn("file name exist ..rename")
            os.rename(log_dir+csvfile, log_dir+csvfile_bak)
        else:
            lgr.info("Write list ..")
            
        with open(log_dir+csvfile,"w") as f:                
            csvwriter = csv.writer(f)
            f.write('\nMTF-Storm ver 1.0 fuzzing run\n')
            #f.write('#---------------------------#\n')
            f.write('\nDate of run:%s\n'%ctime())
            f.write('Fuzzing field :%s \n'%(test_field))
            f.write('\nFC: %d (0x%02X)..,software under test: %s \n'%(function_code,function_code,log_dir))
            f.write("Total no. of rows: %d \n"%(len(tmp_test_list)) )
            f.write('Field names are:' + ', '.join(field for field in test_fields))
            f.write('\n\nTotal rows of test are:\n') 
            
            for row in tmp_test_list: 
            # parsing each column of a row 
                for col in row:
                    f.write("%s,"%col), 
                    #f.write("%10s"%col), 
                f.write('\n') 
        #reset counters        
        self.reset()          
        return            

    def Coverage_of_pair (self,function_code,test_field,test_fields,tmp_list_of_case,t,dir="coverage"):
        """
         this method write results test case and  Coverage  "{:.1%}".format(0.1234)-> '12.3%'. *.csv for test 2-way field '.
         t=256 in field one byte, t=65535 for two byte,
         .append('add_and_qua') case fuzz_session.priority==3:
        """
        rows_of_cover=[]
        test_fields =[x for x in test_fields if x != 'Combinatorial' and x != '2-way']
        if fuzz_session.priority==3:
            test_fields.append('add_and_qua') #
        fields = ['field', 'valid','invalid', 'total coverage % ' ]
        csvfile = log_dir+dir+'/coverage_of_fields_pair_FC%s.csv' %(function_code)

        if not os.path.exists(log_dir+dir):os.makedirs(log_dir+dir)       	 
        elif os.path.exists(log_dir+csvfile):
            lgr.warn("file name exist ..rename")
            os.rename(log_dir+csvfile, log_dir+csvfile_bak)
        else:
            lgr.info("Write list ..")
        
        for i, sublist in enumerate(tmp_list_of_case):
            # data rows of csv file /loop for list_of_case
            coverage=format(float(len(tmp_list_of_case))/t * 100,'.2f')  #total coverage=
            rows_of_cover.append ([test_fields[i],tmp_list_of_case[i][0],tmp_list_of_case[i][1],coverage])
            
        if test_field=='2-way' or test_field=='Combinatorial':
        
            with open(csvfile,"w") as f:
                csvwriter = csv.writer(f)
                f.write('\nMTF-Storm ver 1.0 fuzzing run:\n')
                f.write('\nDate of run:%s\n'%ctime())
                f.write('\nFC: %d (0x%02X)..,software under test: %s \n'%(function_code,function_code,log_dir))
                f.write('column names are:' + ', '.join(field for field in fields))
                f.write('\n\nCoverage for fields 2-way :' + ', '.join(field for field in test_fields))                
                f.write('\n\n\t case of test are:\n\n')
                #f.write('\n\n\tcase and coverage for field no:\n\n')
                
                for row in rows_of_cover[:10]:
                # parsing each column of a row 
                    for col in row: 
                        f.write("\t%10s"%col), 
                    f.write('\n')             
        else:
            lgr.warn("Write error ..")
            
        #reset counters        
        self.reset()          
        return     

    def Coverage (self,function_code,test_field,test_fields,valid,invalid,tmp_test_list,t,dir="coverage"):
        """
        this method write results  Coverage  "{:.1%}".format(0.1234)-> '12.3%'. *.csv for test single field '.
        t=256 in field one byte, t=65535 for two byte
        """
        test_fields =[x for x in test_fields if x != 'Combinatorial' and x != '2-way']
        fields = ['field', 'valid','invalid', 'total coverage % ' ]
        csvfile = log_dir+dir+'/coverage_of_fields_FC%s.csv' %(function_code) 
        if not os.path.exists(log_dir+dir):
             os.makedirs(log_dir+dir)
        elif os.path.exists(log_dir+csvfile):
            lgr.warn("file name exist ..rename")
            os.rename(log_dir+csvfile, log_dir+csvfile_bak)
        else:
            lgr.info("Write list ..")
        
        coverage=format(float(len(tmp_test_list))/t * 100,'.2f')        
        fuzz_session.rows_of_cover.append ([test_field,valid,invalid,coverage])
        if test_field==test_fields[-1] :
        
            with open(csvfile,"w") as f:                    
                csvwriter = csv.writer(f)
                f.write('\nMTF-Storm ver 1.0 fuzzing run:\n')
                f.write('\nDate of run:%s\n'%ctime())
                f.write('\nFC: %d (0x%02X)..,software under test: %s \n'%(function_code,function_code,log_dir))
                f.write('column names are:' + ', '.join(field for field in fields))
                f.write('\n\nCoverage for fields:' + ', '.join(field for field in test_fields))
                f.write('\n\n\tcase and coverage for field no:\n\n')
                
                for row in fuzz_session.rows_of_cover[:10]:
                # parsing each column of a row 
                    for col in row: 
                        f.write("\t%10s"%col), 
                    f.write('\n')                    
        
        else:
            lgr.warn("Write error ..")  #raise ..
            #raise WriteError('Coverage error')
        #reset counters         
        self.reset()                                                                                    
        return     

#-----------------------------------------------------------------------------------------------------------#
# This Class fuzzes / verify function code and mapping address
# list_csv=[],  list of list results of search
#-----------------------------------------------------------------------------------------------------------#
class black_box:
    global csvHeading,list_csv,csvFile,pcap_file,filtered_pcap,csv_Heading_memory,list_of_results,rang_memory
    list_csv=[]                                                             
    csvHeading= ["FC_1","FC_2","IN_REG","COILS","DIS_IN","HO_REG"]
    
    #Define for storege /memory dump attack
    csv_Heading_memory=["address_read","Value"]
    rang_memory=[]                                                  #add addres eg (0,100) as tumple/etch time
    list_of_results=[]                                              #list of list results of search/tuples
    
    def __init__(self,csvFile='',pcap_file=""):
        self.csvFile=csvFile
        self.pcap_file=pcap_file
        self.filtered_pcap=filtered_pcap
               
    def WriteCSVFile (self,csvFile):
        '''
        this method write results of search black box to file csv  
        '''  
        global csvHeading,list_csv
       
        ofile  = open(csvFile, "wb")        
        writer = csv.writer(ofile, delimiter='\t')
        writer.writerow(csvHeading)                                         #making header here
        for values in izip_longest (*list_csv):
            writer.writerow(values)      
        ofile.close()    
   
    
    def WriteCSVblock (self,scv_table):
        '''
        this method write results of  memory dump attack to file csv  each table memory block
         '''
        
        ofile  = open(scv_table, "wb")        
        writer = csv.writer(ofile,delimiter='\t')
        #writer.writerow(csv_Heading_memory)
        for values in izip_longest (rang_memory,list_of_results):
            writer.writerow(values)                                          #making header here             
        ofile.close()  

    
    def setUp(self):
        ''' 
        This method copy for pymodbus 2.3.0 implementension Modbus,test_factory.py 
        '''
        self.request = (
               
                (0x01, '\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, '\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, '\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, '\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07'),                                       # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b'),                                       # get comm event counters
                (0x0c, '\x0c'),                                       # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02\x04\0xff\xff'),          # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' 
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x04\x00'),                           # read device identification                       
        )

        self.response = (
                (0x01, '\x01\x01\x01'),                               # read coils
                (0x02, '\x02\x01\x01'),                               # read discrete inputs
                (0x03, '\x03\x02\x01\x01'),                           # read holding registers
                (0x04, '\x04\x02\x01\x01'),                           # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07\x00'),                                   # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, '\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, '\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' \
                       '\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, '\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )

        self.bad = (
                (0x80, '\x80\x00\x00\x00'),                           # Unknown Function
                (0x81, '\x81\x00\x00\x00'),                           # error message
                (0x90, '\x90\x00\x00\x00'),
                (0x91, '\x91\x00\x00\x00'),
                (0x92, '\x92\x00\x00\x00'),
                (0x93, '\x93\x00\x00\x00'),
                (0x94, '\x94\x00\x00\x00'),
                (0x95, '\x95\x00\x00\x00'),
                (0x96, '\x96\x00\x00\x00'),
                (0x97, '\x97\x00\x00\x00'),
                (0x98, '\x98\x00\x00\x00'),
                (0x99, '\x99\x00\x00\x00'),     
        )
        
        self.exception = (
                (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
                (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
                (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
                (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception
                (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
                (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
                (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
                (0x88, '\x88\x0a\x16\x06'),                           # gateway path unavailable exception
                (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception
        )
        # some diagnostics Response and test ForceListenOnlyMode
        # chech test '\x08\x00\x04'),  ForceListenOnlyModeResponse/listen only mode case not response return
        # after send \x08\x00\x01\x00\x00') if port is not listen only mode return normal Echo else not response
        
        self.diagnostics = (                                        
        
        (00, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (01, '\x08\x00\x01\x00\x00'),                               #restartCommunicationsResponse/live the log but priot restart /echo request
        (02, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (03, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (04, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse/listen only mode case not response return
        (05, '\x08\x00\x01\x00\x00'),                               #restartCommunicationsRequest/if port is not listen only mode return normal Echo else not response
        (06, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (07, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, '\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, '\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, '\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, '\x08\x00\x0f\x00\x00'),                               # ReturnSlaveNoReponseCountResponse
        (14, '\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse
        (15, '\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, '\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, '\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse
        (18, '\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse
        (19, '\x08\x00\x15' + '\x00\x00' * 55),                     #GetClearModbusPlusResponse
        (20, '\x08\x00\x01\xff\x00'),                               #restartCommunicationsResponse/Com Event Log clear 
       )


    def remove_duplicates(self,l):
        return list(set(l))

    '''scan for address coil support, return list support '''    
    def scan_coil(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_COILS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_coil)
        return list
    
    """scan for_address_input_reg support, return list support """   
    def scan_READ_INPUT_REGISTERS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_INPUT_REGISTERS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_input_reg)
        return list
    
    """scan for_address_input_reg support, return list support  """  
    def scan_READ_DISCRETE_INPUTS(self,s_address,l_address,step,list):
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave, READ_DISCRETE_INPUTS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_dist_input)
        return list
    
    """scan for_address_input_reg support, return list support """   
    def scan_READ_HOLDING_REGISTERS(self,s_address,l_address,step,list):
        global num_of_search #demo
        for address_fuz in range (s_address,l_address,step):                    
                response_pdu=master1.execute_f(slave,READ_HOLDING_REGISTERS , address_fuz, quan_step)
                self.get_Supported(address_fuz,response_pdu,list,not_response_address_hold_reg)
        return  list   

    """check list of support address for number of elements min 3 elements  """     
    def chk_list_Up(self,list):
        global step,s_address,l_address,num_of_search
        #init_        
        s_address=fuzz_session.s_address
        l_address=fuzz_session.l_address
        step=fuzz_session.step
                                                     
        if list==supported_address_coil :
            while step!=1 :
                step=step/2
                if  len(list) == 0:                             #empty list                                  
                    self.scan_coil(s_address,l_address,step,list)
                                                                                                            
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)                  
                    if len(list) == 0 :
                        max_el=0
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535              
                    #call
                    self.scan_coil(s_address,l_address,step,list)                                                                           
                                                                   
        elif list==supported_address_input_reg :
            
            while step!=1 :
                step=step/2
                if  len(list) == 0:                           #empty list                                   
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                                            
                else  :                                       #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                                            
                       
        elif list==supported_address_dist_input :
               
            while step!=1 :
                step=step/2
                if  len(list) == 0:                           #empty list                                    
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)                                           
                else  :                                        #first address 0/not empty list
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)                        
                     
        elif list==supported_address_hold_reg :   
            
            while step!=1 :
                step=step/2
                if  len(list) == 0:                            #empty list                
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)                                                                 
                else  :                                       #first address 0/not empty list                
                    #calculate max elements 
                    max_el=max(list)
                    #set s_address is max item of list
                    s_address=max_el
                    l_address=s_address+(2*step)
                    if l_address>65535 :
                        l_address=65535                
                    #call
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)                                                                             
        else :
            pass                
        return   

    """check list of support address for number of elements min 3 elements"""
    def chk_list_down(self,list):
        global step,s_address,l_address
        lgr.info('check list down')
        #l_address=s_address+step
        if len(list) == 0:
            pass        
        elif min(list)!=0 :
            min_el=min(list)
            step=min_el/2
            #init value
            s_address=0
            l_address=min_el                                                           
            while step!=1 :
                step=step/2
                s_address=min(list)-(2*step)
                l_address=min(list)
                
                if list==supported_address_coil:
                    self.scan_coil(s_address,l_address,step,list)
                                                    
                elif list==supported_address_dist_input :
                    self.scan_READ_DISCRETE_INPUTS(s_address,l_address,step,list)                   

                elif list==supported_address_hold_reg :
                    self.scan_READ_HOLDING_REGISTERS(s_address,l_address,step,list)
                    
                elif list==supported_address_input_reg : 
                    self.scan_READ_INPUT_REGISTERS(s_address,l_address,step,list)                                                       
        else :
            pass        
        
        return      

   
    def ReqsupportFunc(self):
        """ Looking for supported function codes with wall pdu request"""     

        supportedFunc = []      
        lgr.info('\n \t  \t Looking for supported function codes..with wall pdu request')       
        for func, msg in self.request:
            response_pdu=master1.execute_master(slave,msg)
            lgr.info('response_pdu: ----->%r '% ByteToHex(response_pdu))                   
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)
                if returnCode > 127 and exceptionCode == 0x01:        #illegal function
                  #If return function code is > 128 --> error code
                  lgr.warn("Function Code "+str(func)+" not supported." )                 
                else:
                  supportedFunc.append(func)
                  lgr.info("Function Code "+str(func)+" is supported." )
            else:
              lgr.warn("Function Code "+str(func)+" probably supported." )
              supportedFunc.append(func) 

        #print function list support
        lgr.info( '"\n"----------------The Function code supported / pdu search--------------' )
        self.print_results_blackbox(FC =supportedFunc)
        return supportedFunc

    
    def getSupportedFunctionCodes(self):
        """ Verifies which function codes are supported by a Modbus Server-copy for modlib.py
        Returns a list with accepted function codes
        """    
      
        supportedFuncCodes = []

        lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic")
        for fct in range(0,127,1):                     
            pdu=struct.pack(">B",fct) + '\x00\x00'+'\x00\x01'
            response_pdu=master1.execute_master(slave,pdu)
            lgr.info('response_pdu: ----->%r '% ByteToHex(response_pdu))                  
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)
                if returnCode > 127 and (exceptionCode == 0x01 or exceptionCode == 0x03):
                  # If return function code is > 128 --> error code
                  lgr.warn("Function Code "+str(fct)+" not supported." )
                  
                else:
                  supportedFuncCodes.append(fct)
                  lgr.info("Function Code "+str(fct)+" is supported." )
            else:
              lgr.warn("Function Code "+str(fct)+" probably supported." )
        #print function list supported        
        lgr.info ('\n-----------    The Function code supported / search FC 1-127  --------------')             
        self.print_results_blackbox(FC =supportedFuncCodes)
        return supportedFuncCodes

    """ NOT use in this time /RTU """
    def getSupportedDiagnostics(self):                     

        supportedDiagnostics = []
     
        lgr.info( "Looking for supported diagnostics codes..")
        for i in range(0,65535):       # Total of 65535, function code 8, sub-function code is 2 bytes long
          pdu="\x08"+struct.pack(">H",i)+"\x00\x00"
          response=master1.execute_master(slave,pdu)

          # We are using the raw data format, because not all function
          # codes are supported by this library.
          if response:              
              data = str(ans)
              data2 = data.encode('hex')              
              returnCode = int(data2[14:16],16)
              exceptionCode = int(data2[17:18],16)

              if returnCode > 127 and exceptionCode == 0x01:
                # If return function code is > 128 --> error code
                lgr.warn ("Function Code "+str(i)+" not supported.")
              else:
                supportedDiagnostics.append(i)
                lgr.info ("Diagnostics Code "+str(i)+" is supported")
          else:
            lgr.warn("Diagnostics Code "+str(i)+" probably supported.")
            supportedDiagnostics.append(i)

        return supportedDiagnostics  
    
    def get_Supported(self,address_fuz,response_pdu,mylist,not_resp_list): 
        """ Verifies which address are supported ,Returns a list with accepted address""" 

        returnCode=""
        exceptionCode =""
        lgr.info('The response_pdu :%r'%ByteToHex(response_pdu))
        if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)
                lgr.info( 'The function_code is %d ' % returnCode) 
                if returnCode > 127 and (exceptionCode == 0x02):  
                  # If return function code is > 128 --> error code
                  lgr.warn("Fuzz_address "+str(address_fuz)+" not supported." )
                  lgr.info('')
                else:
                    if address_fuz not in mylist :                                  #if item exist in list, not append
                        mylist.append(address_fuz)
                        lgr.info("Fuzz_address  "+str(address_fuz)+" is supported." )
                        lgr.info('')
                    else :
                        lgr.info("Fuzz_address  "+str(address_fuz)+" is supported." )
                        lgr.info('')
        else :
              lgr.warn("Fuzz_address  "+str(address_fuz)+" probably supported." )
              #add in list of support address
              mylist.append(address_fuz)
              #add in list for not support address list for use possible later
              not_resp_list.append(address_fuz)
              
        return  mylist.sort(),not_resp_list.sort()   

   
    def printmap_address(self,*args):
    #print supported address ..for data bank  - -NOT USE"""
    
        for arg in args :       
            print >>sys.stderr, '"\n"----Check for' +'%r' %arg + 'address  supported --------------'          
            print(" ".join(map(str, list)))
        return   
  
    def getaddress(self):
       """ Check for supported address ..for data bank """
    
       global step,value_range,l_address,s_address
       response_pdu=""
       #-------------------------------------------------------------------------------------#
       lgr.info('\n \t \t Looking for READ_COILS, supported address ..')      
       #check elements of the list support address/upper   
       self.chk_list_Up(supported_address_coil)
       #if min item of list not 0
       self.chk_list_down(supported_address_coil)
       #-------------------------------------------------------------------------------------#
       """Check that response for read analog inputs (READ_INPUT_REGISTERS) function is ok"""
       lgr.info('\n \t \t Looking for READ_INPUT_REGISTERS supported address ..')         
       self.chk_list_Up(supported_address_input_reg)      
       #if min item of list not 0
       self.chk_list_down(supported_address_input_reg)
       #--------------------------------------------------------------------------------------#
       """Check that response for read digital inputs function is ok""" 
       lgr.info('\n \t \t Looking for READ_DISCRETE_INPUTS  supported address ....')      
       self.chk_list_Up(supported_address_dist_input)     
       #if min item of list not 0
       self.chk_list_down(supported_address_dist_input)
       #--------------------------------------------------------------------------------------#
       """Check that response for READ_HOLDING_REGISTERS function is ok"""  
       lgr.info('\n \t \t Looking for READ_HOLDING_REGISTERS  supported address ..')    
       self.chk_list_Up(supported_address_hold_reg)
       #if min item of list not 0
       self.chk_list_down(supported_address_hold_reg) 
       #-------------------------------------------------------------------------------------#
       #print  elements of the list support address
       lgr.info ('\n-----------------    Check for address  supported    ----------------------')        
       self.print_results_blackbox(COILS =supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
       self.print_results_blackbox(NOT_RESP_COILS =not_response_address_coil,NOT_RESP_INPUT_REGISTERS=not_response_address_input_reg,NOT_RESP_DISCRETE_INPUTS=not_response_address_dist_input,NOT_RESP_HOLDING_REGISTERS=not_response_address_hold_reg)
      
       return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg 
    
    """
          Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
          object Id Object Name / Description   Type   M/O    category  
     
          0x00  VendorName                   ASCII String  Mandatory  Basic 
          0x01  ProductCode                  ASCII String  Mandatory
          0x02  MajorMinorRevision           ASCII String  Mandatory
          -----------------------------------------------------------------
          0x03  VendorUrl                    ASCII String  Optional   Regular
          0x04  ProductName                  ASCII String  Optional 
          0x05  ModelName                    ASCII String  Optional 
          0x06  UserApplicationName          ASCII String  Optional 
          0x07  Reserved                                   Optional
          …
          0x7F 
          ---------------------------------------------------------------------                                     
          0x80  Private objects may be  optionally                     Extended  
          …
          0xFF The range [0x80–0xFF]                        Optional  
          is Product device dependant                                         
          ----------------------------------------------------------------------- 
          
            Read Device ID code /read_code
            DeviceInformation_Basic:  0x01 , 
            DeviceInformation_Regular= 0x02 ,
            DeviceInformation_Extended= 0x03 ,
            DeviceInformation_Specific= 0x04 , 
       If the Object Id does not match any known object, the server responds as if object 0 were 
       pointed out (restart at the beginning)  
       params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] } dictionary
       handle  = ReadDeviceInformationRequest(**params)
    """      
    
    def Read_Device_Information(self):
        """basic message encoding """
        
        mei_object=[]                                
        lgr.info('\n  \t \t  Looking for FC 43 : READ Device Information SubFC :14')
        # Read Device ID code
        for read_code in range(1,5,1) :                                    
            for object_id in range(0,127,1) :
                handle  = ReadDeviceInformationRequest(read_code,object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=master1.execute_master(slave,result)
                if response:                
                    data = str(response)
                    data2 = data.encode('hex')               
                    returnCode = int(data2[0:2],16)
                    exceptionCode = int(data2[3:4],16)
                    # If return function code is > 128 --> error code    
                    if returnCode > 127 and (exceptionCode == 0x02 or exceptionCode == 0x01 or exceptionCode == 0x03):
                        
                        lgr.info('- response :   ---> %r exceptionCode : %r  ' % (ByteToHex(response),exceptionCode))
                        continue
                         
                    else :                
                        message = response[1:len(response)]          #parse_response FC=43
                        if len(message)<6 :
                            lgr.info('response message ---> : %r' % ByteToHex(message))
                            continue
                         
                        '''read device information MESSAGE response  decode '''       
                        handle  = ReadDeviceInformationResponse()    # send to decode
                        handle.decode(message)   
                        lgr.info('Read Device ID code : %d '% handle.read_code )
                        lgr.info('Read Device ID code : %d '% object_id)             
                        lgr.info('Read Device ID code : %d' % handle.conformity )
                    
                        #if  Object is in list ...
                        if handle.information not in  mei_object :                
                              mei_object.append(dict(handle.information))
                else :
                    lgr.info('- response :   ---> %r ' % ByteToHex(response))
                                                  
        lgr.info('\n  \t \t Test device identification summary creation .....' )        
        lgr.info("\n".join(map(str, mei_object))) 
        lgr.info("\n".join(map(str, mei_object)))         

    
    def print_results_blackbox(self,**kwargs):
        """
        print  in log supported address ..for data bank and result from 
        send request wall response/bad/exception 
        """
          
        lgr.info('')
        for name, value in kwargs.items():
            #print '{0} = {1}'.format(name, value)
            lgr.info( '{0} = {1}'.format(name, value))
          #print >>sys.stderr, '                                                                              '    
        lgr.info('')
        return              
    
    def request_check(self):
        """Looking for send  some PDU for error message as bad,response, exception and diagnostic (response) 
        some diagnostics Response and test ForceListenOnlyMode
        chech test '\x08\x00\x04'),  ForceListenOnlyModeResponse/listen only mode case not response return
        after send \x08\x00\x01\x00\x00') if port is not listen only mode return normal Echo else not response
        look in diagnostics list
        """
    
        check_response1 = []
        check_response2 = []
        check_response3 = []
        check_response4 = []
        
        lgr.info('\n \t \t \t .........send  wall  response..'  )
        for func, msg in self.response:
            response_pdu=master1.execute_master(slave,msg)
            check_response1.append(ByteToHex(response_pdu))
            lgr.info('response pdu ----->:%r ' % ByteToHex(response_pdu))                  
        
        lgr.info('\n \t \t \t ------ send  request bad..'  )
        for func, msg in self.bad:
            response_pdu=master1.execute_master(slave,msg)
            check_response2.append(ByteToHex(response_pdu))
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))   
        
        lgr.info('\n  \t \t \t ..........send  exception ....')
        for func, msg in self.exception:
            response_pdu=master1.execute_master(slave,msg)
            check_response3.append(ByteToHex(response_pdu))
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))
        
        lgr.info('\n \t \t \t ........send common diagnostics response..')    
        for func, msg in self.diagnostics:
            response_pdu=master1.execute_master(slave,msg)
            check_response4.append(ByteToHex(response_pdu))
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))         
        
        lgr.info ('\n----------------Response of request --------------')
        self.print_results_blackbox(response =check_response1,bad=check_response2,exception=check_response3,diagnostics=check_response4)

        return check_response1,check_response2,check_response3,check_response4

        """
        Check black_box and save csv file 
        search.csv /file format/
        FC_1    --> Verifies which function codes are (1-127) with ModbusPDU_Generic ....
        FC_2    --> create Supported Function Codes for send request wall pdu 
        IN_REG  --> Looking for INPUT_REGISTERS  supported address
        COILS   --> Looking for READ_coil  supported address
        DIS_IN  --> Looking for DISCRETE_INPUTS  supported address
        HO_REG  --> Looking for READ_HOLDING_REGISTERS  supported address
    
   
        FC_1  FC_2    IN_REG  COILS   DIS_IN  HO_REG
           1    20       0      0        0       0
           2    43    1024    1024    1024    1024
           3          2048            2048
           4          3072            3072      ...
       ..         ....
    
        """    

    def con_SUT (self):
        """ Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False """
        
        global forever,search_mode,csvFile
        
        try:

            lgr.info('\n \t Verifies which function codes are supported  .....') 
            l1=self.getSupportedFunctionCodes()   
            
            #Add to clobal list the return list/list of list
            list_csv.append(l1)  
            
            """
            Function send request wall pdu request and from response create Supported Function Codes  list,
            Add to clobal list the return lists 
            
            """ 
            lgr.info('\n \t create Supported Function Codes for send request wall pdu  .... .....') 
            self.setUp()
            l2=self.ReqsupportFunc()
            list_csv.append(l2)
                         
            """ mapping address table      """
            lgr.info('mapping address table ....')
            l3,l4,l5,l6=self.getaddress()

            """ case empty list / the PLC not response in address/return empty address list"""
            if len(l3) == 0:
                l3=[0,65535]
            if len(l4)==0  : 
                l4=[0,65535]
            if len(l5) == 0:
                l5=[0,65535]
            if len(l6) == 0:
                l6=[0,65535]       

            list_csv.append(l3)
            list_csv.append(l4)
            list_csv.append(l5)
            list_csv.append(l6)
           
            """ send request wall response/bad/exception """
            lgr.info ('send request wall response/bad/exception ....')
            self.setUp() 
            self.request_check()
          
            """ search Device_Information """                 
            self.Read_Device_Information()

            """ Write to csv search results of blackbox/reconnaissance """ 
            self.WriteCSVFile(csvFile)
            
            """ memory read dump attack"""
            self.memory_dump()           
                                                                           
        except modbus_b.ModbusError, ex:
           
           lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
           pass                                  
      
        except socket.timeout:
            
            lgr.error('Socket timeout, loop and try recv() again')
            time.sleep( 1.0)
            pass    
        
        except socket.error as socketerror:
            lgr.error("Socket Error: %s ", (socketerror))
            time.sleep( 1.0)
            do_work(True)                                                     
        
        except:                                                                                          
            lgr.error('Other Socket err, exit and try creating socket again')  # fix raise
            traceback.print_exc()                
            time.sleep(1.0)
          
        finally:
                master1.close()                                        
                lgr.info("Finally! search all DONE !!.")                    
                                                        
    def memory_dump(self):
        
        """ Read csv file and memory dump attacks-scv_table='dump_memory.csv'/file format/

        Address 0x    --> address and offset (eg ox for COILS) ....        
        Value READ_COILS  --> Value from address    
    
       "Address 0x   Value READ_COILS"  
        (1, 100)    (0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 1....)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, ....)
        ...................
        Address 3x   Value READ_INPUT_REGISTERS "   
        (1, 100)    (3333, 1, 2, 3, 0, 5, 0, 0, 0,  0, 0, 0, 0, 0, ... 0, 0, 0, 0, ..)
        (101, 200)  (0, 0, 0, 0, 0, 0, 0, 0, 0,...)

        ..........................................
      
        """    
        global slave,rang_memory,list_of_results, quantity, scv_table,step_mem_dump
        #create an empty list
        FCValues0 = []                                             
        FCValues1 = []
        IN_REG=[] 
        COILS=[]
        DIS_IN =[]
        HO_REG=[]

        try :
                values = csv.reader(open('search.csv', 'rb'), delimiter='\t')
                #read 0 colume
                for row in values:
                      FCValues0.append(row[0])
                      FCValues1.append(row[1])
                      IN_REG.append(row[2])
                      COILS.append(row[3])
                      DIS_IN.append(row[4])
                      HO_REG.append(row[5])    
                # pop header
                FCValues0.pop(0)    
                FCValues1.pop(0)    
                IN_REG.pop(0)   
                COILS.pop(0)    
                DIS_IN.pop(0)   
                HO_REG.pop(0)

                IN_REG = filter(None,IN_REG)
                COILS = filter(None,COILS)
                DIS_IN= filter(None,DIS_IN)
                HO_REG = filter(None,HO_REG)
                                                           
                #convert all strings in a list to ints
                IN_REG = [int(i) for i in IN_REG]
                COILS = [int(i) for i in COILS]
                DIS_IN = [int(i) for i in DIS_IN]
                HO_REG = [int(i) for i in HO_REG]  
                
                #for all list min/max address                            
                MIN_COILS =min(COILS )
                MAX_COILS =max(COILS )
                MIN_IN_REG=min(IN_REG)
                MAX_IN_REG=max(IN_REG)
                MIN_DIS_IN=min(DIS_IN)
                MAX_DIS_IN=max(DIS_IN)
                MIN_HO_REG=min(HO_REG)
                MAX_HO_REG=max(HO_REG)
                                                          
                # Search for  Read the contents of all PLC data blocks    
                lgr.info( 'Memory dump READ REGISTERS .... ....')
                lgr.info('\n')
                      
                lgr.info('---------------------------- Set Configuration for memory dump attacks--------------------------------------------------------')
                lgr.info('start_address READ_COILS : %d' %MIN_COILS )
                lgr.info('last_address READ_COILS : %d' %MAX_COILS )
                lgr.info('start_address READ_DISCRETE_INPUTS: %d' %MIN_DIS_IN)
                lgr.info('last_address READ_DISCRETE_INPUTS: %d' %MAX_DIS_IN)
                lgr.info('start_address READ_HOLDING_REGISTERS: %d' %MIN_HO_REG)
                lgr.info('last_address READ_HOLDING_REGISTERS: %d' %MAX_HO_REG)
                lgr.info('start_address READ_INPUT_REGISTERS: %d' %MIN_IN_REG)
                lgr.info('last_address READ_INPUT_REGISTERS: %d' %MAX_IN_REG)
                
                # Test  response for read coils (READ_COILS)               
                # This function code is used to read from 1 to 2000 contiguous status of coils in a remote
                # device"""
                
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_COILS  ....(%d,%d) .offset:0X' % (MIN_COILS,MAX_COILS))                
                rang_memory.append('Address 0x \t Value READ_COILS')
                list_of_results.append('',) 
                
                for address_read in range (MIN_COILS,MAX_COILS,step_mem_dump):                    
                        
                        if (address_read+quantity)>MAX_COILS :
                            quantity=(MAX_COILS-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        #write head for csv file
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_COILS , address_read , quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))
                        #add results for list tuples
                        list_of_results.append(result,)                     
               
                # Test  response for read digital inputs function (READ_DISCRETE_INPUTS )               
                # This function code is used to read from 1 to 2000 contiguous status of discrete inputs in a
                # remote device"""                    
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_DISCRETE_INPUTS ..(%d,%d).offset:1X'%(MIN_DIS_IN,MAX_DIS_IN))
                #offset_dis_input=10000
                rang_memory.append('Address 1x \t Value READ_DISCRETE_INPUTS ')
                list_of_results.append('',) 
                for address_read in range (MIN_DIS_IN,MAX_DIS_IN,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_DIS_IN :
                            quantity=(MAX_DIS_IN-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_DISCRETE_INPUTS, address_read , quantity)                    
                        lgr.info('Answer >> result  %s '  % (result,))
                        list_of_results.append(result,)
                                  
                # Test  response for read READ_INPUT_REGISTERS (READ_INPUT_REGISTERS )               
                # This function code is used to read from 1 to 125 contiguous input registers in a remote device               
                lgr.info('\n')
                lgr.info('\t \t Memory dump READ_INPUT_REGISTERS ..(%d,%d)..offset: 3X' %(MIN_IN_REG,MAX_IN_REG))
                #offset_reg_in= 30000
                rang_memory.append('Address 3x \t Value READ_INPUT_REGISTERS ')
                list_of_results.append('',) 
                for address_read in range (MIN_IN_REG,MAX_IN_REG,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_IN_REG :
                            quantity=(MAX_IN_REG-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_INPUT_REGISTERS , address_read , quantity)    #tuple                  
                        lgr.info('Answer >> result  %s '  % (result,))
                        list_of_results.append(result,)                                          

                # Test  response for read HOLDING_REGISTERS  (HOLDING_REGISTERS )               
                # This function code is used to read from 1 to 125 contiguous holding registers in a remote device"""
                # Address 40001
                lgr.info('\n')
                lgr.info('\t \t Memory dump HOLDING_REGISTERS  ..(%d,%d)..offset:4X' % (MIN_HO_REG,MAX_HO_REG))
                rang_memory.append('Address 4x \t Value HOLDING_REGISTERS')
                list_of_results.append('',)
                #offset_reg= 40000
                for address_read in range (MIN_HO_REG,MAX_HO_REG ,step_mem_dump):                    
                        quantity=step_mem_dump
                        if (address_read+quantity)>MAX_HO_REG :
                            quantity=(MAX_HO_REG-address_read)
                        lgr.info('\n')
                        lgr.info('first address_read  %s (%s) last_address %s (%s)' % ((address_read+1),hex(address_read+1),(address_read+quantity),hex(address_read+quantity)))
                        rang_memory.append((address_read+1,address_read+quantity))
                        result=master1.execute_read_memory(slave, READ_HOLDING_REGISTERS , address_read , quantity)        #tuple                
                        lgr.info('Answer >> result  %s '  % (result,))
                        list_of_results.append(result,)     
                
                #Call function to write csv file
                self.WriteCSVblock(scv_table)                
        except IOError:
                lgr.error('No such file or directory: search.csv')
                sys.exit(1)       
        except :
                traceback.print_exc() 
                lgr.error('error')
                pass        
                    
    #-----------------------------------------------------------------------------------------------------#
    # add functions for read pcap file and write in csv file 
    # ----------------------------------------------------------------------------------------------------#
    def con_SUT_pcap (self):
            global forever,search_mode,csvFile,pcap_file,filtered_pcap,mod_file_response,mod_file_request
                            
            try:
                l2=[]                                                     
                #scan  function support for pcap file 
                #Verifies which function codes are supported returns a list with accepted function codes/ fuzz_mode=False
                lgr.info('\n \t Verifies which function codes are supported  .....') 
                l1=self.get_pkt(pcap_file)             
                 
                #Add to clobal list the return list/list of list
                list_csv.append(l1)
                list_csv.append(l2)
                             
                #mapping address table   """   
                lgr.info ('mapping address table ....')
                
                l3,l4,l5,l6=self.getadd_pcap(filtered_pcap)
                #case empty list / the PLC not response in address/return empty address list
                if len(l3) == 0:
                    l3=[0,65535]
                if len(l4)==0  : 
                    l4=[0,65535]
                if len(l5) == 0:
                    l5=[0,65535]
                if len(l6) == 0:
                    l6=[0,65535]       

                list_csv.append(l3)
                list_csv.append(l4)
                list_csv.append(l5)
                list_csv.append(l6)
                            
                # Write to csv search results of search  pcap file 
                self.WriteCSVFile(csvFile)
                                                                                                                                             
            except  (KeyboardInterrupt, SystemExit):
                lgr.info( "You hit control-c")
                raise
            
            except Scapy_Exception as msg:
                print msg, "Scapy problem ..."
                raise    
            
            except IOError as err:
                print err.errno 
                print err.strerror
                           
            except:                                                             
                lgr.error('Other err, continue ')
                traceback.print_exc()
                pass
                                             
            finally:                                        
                lgr.info("Finally! search all DONE !!.")                    
                
#----------------------------------------------------------------------------------------
# This function reads a pcap file /filtered_pcap and returns a packet object.                                                                     
#----------------------------------------------------------------------------------------
    def read_pcap(self,filtered_pcap):
        while not( os.path.isfile(filtered_pcap) and os.path.getsize(filtered_pcap) > 0 ):
            pass
        pkts=rdpcap(filtered_pcap)
        if len(pkts) > 0:
            return pkts[0]
        else:
            return None    

    #remove payload after TCP /not use
    def payload_strip(pkt):
        lgr.info('payload strip')              
        cur_payload = pkt[TCP]         
        adu_pdu=cur_payload.payload      
        hexdump(adu_pdu)                
        return adu_pdu

    # read packet for pcap file  and  look for supported function codes with library modbus.py 
    def get_pkt(self,pcap_file):
        supportedFuncCodes = [];pkt_cn=0  
        lgr.info("\n \t  \t Looking for supported function codes (1-127) with ModbusPDU_Generic from pcap file")        
        #filter by protocol, ModbusADU
        #save in filtered.pcap/request and response
        self.filter_pcap(pcap_file)                            
        #filtered_pcap= filtered.pcap 
        self.filter_pcap_response(filtered_pcap)                  
        #parsing/ scapy library/mod_file_response=filter_resp.pcap 
        pkts=rdpcap(mod_file_response)                          
        
        for pkt in pkts:
            pkt_cn +=1
            cur_payload = pkt[ModbusADU_Answer]
            pdu=cur_payload.payload           
            response_pdu=str(pdu) 
                                       
        # We are using the raw data format, because not all function
        # codes are supported out by this library.
            if response_pdu:                
                data = str(response_pdu)
                data2 = data.encode('hex')               
                returnCode = int(data2[0:2],16)
                exceptionCode = int(data2[3:4],16)

                if returnCode > 127 and (exceptionCode == 0x01 or exceptionCode==0x03 )  :
                    # If return function code is > 128 --> error code
                    lgr.warn("Function Code "+str(returnCode )+" not supported." )                  

                elif returnCode > 127 and (exceptionCode == 0x01  or exceptionCode==0x03 or exceptionCode==0x02 or exceptionCode==0x04):
                    fcn= returnCode-128                       #exeptionCode = fc+128
                    if fcn not in supportedFuncCodes:
                        supportedFuncCodes.append(fcn)
                        lgr.info("Function Code "+str(fcn)+" is supported." )                          
                
                # If return function code is < 128 --> support                              
                elif returnCode < 127 :
                    if returnCode not in supportedFuncCodes:
                        supportedFuncCodes.append(returnCode)
                        lgr.info("Function Code "+str(returnCode)+" is supported." )                
                else :
                    lgr.warn("returnCode "+str(returnCode )+" and exceptionCode"+str(exceptionCode))                                       
            else:
                lgr.warn("Function Code "+str(returnCode)+" probably supported.")
        #supportedFuncCodes.append(returnCode)
        supportedFuncCodes.sort()                                                                         
        #print function list supported 
        lgr.info('\n \t  \t Total packets read -----> %d '% pkt_cn)                   
        lgr.info( '\n-----------    The Function code supported --------------')              
        self.print_results_blackbox(FC =supportedFuncCodes)
        
        return supportedFuncCodes

   #filter by protocol, ModbusADU/capture request and  response packet Modbus
    def filter_pcap(self,pcap_file):   
        pkts = rdpcap(pcap_file)
        ports = [502]
        lgr.info('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            ((pkt[TCP].sport in ports and pkt.getlayer(ModbusADU_Answer) is not None) or (pkt[TCP].dport in ports and pkt.getlayer(ModbusADU))))
        wrpcap('filtered.pcap', filtered)   

    #filter by protocol, ModbusADU/ capture  response packet Modbus
    #filtered_pcap=filtered.pcap
    def filter_pcap_response(self,filtered_pcap):   
        pkts = rdpcap(filtered_pcap)                
        ports = [502]
        lgr.info('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].sport in ports and pkt.getlayer(ModbusADU_Answer) is not None))
        wrpcap(mod_file_response, filtered)

    #filter by protocol, ModbusADU/ capture  request packet Modbus
    #filtered_pcap=filtered.pcap
    def filter_pcap_request(self,filtered_pcap):   
        pkts = rdpcap(filtered_pcap)                
        ports = [502]
        lgr.info('packets filtered ...')    
        filtered = (pkt for pkt in pkts if
            TCP in pkt and
            (pkt[TCP].dport in ports and pkt.getlayer(ModbusADU) is not None))
        wrpcap(mod_file_request, filtered)        
    
    #-------------------------------------------------------------------------------------    
    # from request pdu in pcap file /Decode request
    # Verifies which address are supported 
    # Returns a list with accepted address
    #-------------------------------------------------------------------------------------  
    def getadd_pcap(self,filtered_pcap):                                        
        #list of supported address   
        supported_address_coil = []
        supported_address_input_reg = []
        supported_address_dist_input = []
        supported_address_hold_reg = []

        #filter by protocol, ModbusADU/create filtered_request.pcap
        self.filter_pcap_request(filtered_pcap) 
        lgr.info("\n \t  \t Looking for supported address")   
        # mod_file_request='filter_reg.pcap'
        pkts=rdpcap(mod_file_request)                                                     
        num_packets=len(pkts)                                  
       
        # read from pkts                
        for pkt in pkts:                                                                         
        
            try:
                cur_payload = pkt[ModbusADU]                                                #remove payload after TCP
                if cur_payload is None :   
                    lgr.info("Not payload ModbusADU")
                    continue
                r_pdu=cur_payload.payload           
                pdu=str(r_pdu) 
                function_code, = struct.unpack(">B", pdu[0])                                #extract function_code from support fc           
                lgr.info('Detected function_code is % s'  % function_code)                  #return tumple

                if (function_code == READ_INPUT_REGISTERS) or (function_code == READ_HOLDING_REGISTERS) or (function_code == READ_COILS) or (function_code == READ_DISCRETE_INPUTS):
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info('The read_address is % s ' % starting_address) 
                    
                    #used to read from 1 to 125 contiguous input registers/starting_address+
                    if function_code == READ_INPUT_REGISTERS:
                        #add  address in list
                        supported_address_input_reg.extend(range(starting_address,starting_address+quantity_of_x))
                        lgr.info("READ_INPUT_REGISTERS address " + str(range(starting_address,starting_address+quantity_of_x))+" is supported." )
                    
                    #Quantity of Registers / 1 to 125 (0x7D)
                    elif function_code == READ_HOLDING_REGISTERS: 
                        #add in address in list
                        supported_address_hold_reg.extend(range(starting_address,starting_address+quantity_of_x)) 
                        #supported_address_hold_reg.append(starting_address)
                        lgr.info("READ_HOLDING_REGISTERS address  "+ str(range(starting_address,starting_address+quantity_of_x))+" is supported." )

                    # Single bit/read from 1 to 2000 contiguous status of coils /Quantity of Outputs / 8, if the remainder is different of 0 N = N+1        
                    elif function_code == READ_COILS: 
                        #add in address in list
                        #byte_count = quantity_of_x / 8  if (quantity_of_x % 8) > 0:
                        supported_address_coil.extend(range(starting_address,starting_address+quantity_of_x))
                        lgr.info("READ_COILS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported." )

                    elif function_code == READ_DISCRETE_INPUTS: 
                        #add in address in list
                        supported_address_dist_input.extend(range(starting_address,starting_address+quantity_of_x))
                        lgr.info("READ_DISCRETE_INPUTS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported")
                
                    else :
                        pass  
                    

                elif function_code == WRITE_SINGLE_COIL or function_code == WRITE_SINGLE_REGISTER:
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    
                    if function_code == WRITE_SINGLE_COIL :
                        #add in address in list
                        supported_address_coil.append(starting_address)
                        lgr.info("WRITE_SINGLE_COIL address  "+str(starting_address)+" is supported." ) 


                elif function_code == WRITE_SINGLE_REGISTER:
                    # add in address in list
                    supported_address_hold_reg.append(starting_address)
                    lgr.info("WRITE_SINGLE_REGISTER address  "+str(starting_address)+" is supported." )     
            
                elif function_code == WRITE_MULTIPLE_REGISTERS  :

                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    lgr.info('write_address is %s ' % starting_address,)

                    if function_code == WRITE_MULTIPLE_REGISTERS :
                        #add in address in list,calculate quantity_of_x 
                        supported_address_hold_reg.extend(range(starting_address,starting_address+quantity_of_x))        
                        lgr.info("WRITE_MULTIPLE_REGISTERS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported." )

                elif function_code == WRITE_MULTIPLE_COILS:
                    #add in address in list,#calculate quantity_of_x 
                    supported_address_coil.extend(range(starting_address,starting_address+quantity_of_x))     
                    #add    starting_address + quantity_of_x
                    lgr.info("WRITE_MULTIPLE_COILS address  "+str(range(starting_address,starting_address+quantity_of_x))+" is supported." )
         
                elif function_code == Read_File_record :
                    lgr.info("Not implemented yet ..." )                    
                    pass

                # Write File Record  fc 21"""  
                elif function_code == Write_File_record : 
                    lgr.info("Not implemented yet ..." )
                    pass        

                #22 (0x16) Mask Write Register """
                elif function_code == Mask_Write_Register :
                    starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
                    supported_address_hold_reg.append(starting_address)     
                    lgr.info("Mask Write Register address  "+str(starting_address)+" is supported." )


                #24 (0x18) Read FIFO Queue"""
                elif function_code == Read_FIFO_queue :
                    starting_address,=struct.unpack(">H", pdu[1:3])
                    supported_address_hold_reg.append(starting_address)
                    lgr.info("Read_FIFO_queue address  "+str(starting_address)+" is supported." ) 
                    
                # 23 /( 0x17) Read_Write_Multiple_Registers -ok"""
                elif function_code == Read_Write_Multiple_Registers  :
                    #Decode request 
                    read_address, read_count, write_address, write_count,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
                    #calculate read_count/write_count
                    supported_address_hold_reg.extend(range(read_address,read_address+read_count))                                 
                    lgr.info("Read_Multiple_Registers address  "+str(range(read_address,read_address+read_count))+" is supported." ) 
                    
                    supported_address_hold_reg.extend(range(write_address,write_address+write_count)) 
                    lgr.info("Write_Multiple_Registers address  "+str(range(write_address,write_address+write_count))+" is supported.")            
                    
                else :
                    pass
                                
            except Scapy_Exception as msg:
                lgr.error('error, Scapy problem!!" ..')
                raise
            
            except:  #default--raise                                                                            
                lgr.error('error, parse packet ..')                                  
                continue                
        
        lgr.info('\n \t \t Total packets read -----> %d' % num_packets)
        
        #CALCULATE MAX MIN address for each list 
        MIN_COILS =min(supported_address_coil)
        MAX_COILS =max(supported_address_coil)
              
        #remove dumplicate item
        supported_address_coil = list(set(supported_address_coil))
        supported_address_input_reg = list(set(supported_address_input_reg))
        supported_address_dist_input = list(set(supported_address_dist_input))
        supported_address_hold_reg= list(set(supported_address_hold_reg))
        
        #Sort list 
        supported_address_coil.sort()
        supported_address_input_reg.sort()
        supported_address_dist_input.sort()
        supported_address_hold_reg.sort()

        lgr.info( '\n-----------------    Check for address  supported /pcap   ----------------------')        
        self.print_results_blackbox(COILS=supported_address_coil,INPUT_REGISTERS=supported_address_input_reg,DISCRETE_INPUTS=supported_address_dist_input,HOLDING_REGISTERS=supported_address_hold_reg)          
       
        return  supported_address_input_reg,supported_address_coil,supported_address_dist_input,supported_address_hold_reg     
            
#-----------------------------------------------------------------------------------------       
#This is setup master object and generate of test cases peer FC
#-----------------------------------------------------------------------------------------

class SetupAndTeardown(object):
    #set--add 30.03.20
    lof=list_of_fuzz()    
    fuzz_session.illegal_pdu_len=lof.illegal_len_list()
    fuzz_session.bytehex=lof.iter_byte_string_list()

    def __init__(self,host="localhost", port=502, timeout_in_sec=1.0):

        self._timeout = timeout_in_sec
        self._host = host
        self._port = port
        self._is_opened = False
        
        
    def setUp(self):            
        self.master1 = modbus_tcp_b.TcpMaster_b()
        self.master1.set_timeout(1.0)
        self.master1.open()
        time.sleep(1.0)
    
    def tearDown(self):
        self.master1.close()

    #demo test 
    def recon_do_work(self,ever=True) :
        global host               
        
        MAXIMUM_NUMBER_OF_ATTEMPTS=3                        
        lgr.info("Creating the socket reconnect")
        master1.__init__(host=host, port=502, timeout_in_sec=5.0)

        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
            try:           
                master1.open_b()
                lgr.info(''); lgr.info('\t Socket connect worked!')
                break;                                                           
            # except EnvironmentError as exc:
            except socket.error:
                lgr.error('Socket connect failed! Loop up and try socket again') 
                time.sleep(1.0);continue               
        else :                
                lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)                            
                lgr.info("Fuzzer terminate !!.")
                info(start_time,num_of_request)       # info time and request
                master1.close();sys.exit(1)
                

    def con (self):
                global forever          
                t=TestQueries()
                tsf=TestQueriesSerialFC()
                while True:                                                                          

                    try:     
                       
                        if READ_COILS in fuzz_session.FCmergedlist:
                            
                            """Check that read coil queries are handled correctly """
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 01 : READ_COILS .... ')
                            t.test_readcoil()   
                            lgr.info('\t Finally! Fuzz testing  READ_COILS  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(READ_COILS)                           
                            
                        elif READ_DISCRETE_INPUTS in fuzz_session.FCmergedlist :       

                            """Check that ReadDiscreteInputs queries are handled correctly"""                            
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 02 : READ_DISCRETE_INPUTS.... ') 
                            t.test_ReadDiscreteInputs()
                            lgr.info('\t Finally!  Fuzz testing  READ_DISCRETE_INPUTS!!.' )
                            fuzz_session.FCmergedlist.remove(READ_DISCRETE_INPUTS)
                           
                        elif READ_HOLDING_REGISTERS in fuzz_session.FCmergedlist : 
                           
                            """Check that  HOLDING_REGISTERS queries are handled correctly"""                           
                            lgr.info('')
                            lgr.info(' \t Fuzzing  FC 03 : READ_HOLDING_REGISTERS .... ')
                            t.test_readhr()
                            lgr.info(' \t Finally!  Fuzz testing  READ_HOLDING_REGISTERS DONE !!.' )
                            fuzz_session.FCmergedlist.remove(READ_HOLDING_REGISTERS)
 

                        elif READ_INPUT_REGISTERS  in fuzz_session.FCmergedlist :
                                                   
                            """Check that  queries READ_INPUT_REGISTERS are handled correctly"""
                            lgr.info(' \t Fuzzing  FC 04 : READ_INPUT_REGISTERS... ') 
                            t.test_ReadAnalogInputs()
                            lgr.info('\t Finally! Fuzz testing  READ_INPUT_REGISTERS  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(READ_INPUT_REGISTERS)

                              
                        elif WRITE_SINGLE_COIL in fuzz_session.FCmergedlist :
                           
                            """Check that write coil queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 05 : WRITE_SINGLE_COIL .... ')
                            t.test_writecoil()
                            lgr.info('\t Finally!  Fuzz testing WRITE_SINGLE_COIL  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_SINGLE_COIL)

                        
                        elif WRITE_SINGLE_REGISTER in fuzz_session.FCmergedlist :

                            """Check that write HOLDING_REGISTERS queries are handled correctly"""                          
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 06 : WRITE_SINGLE_REGISTER.... ')
                            t.test_writesingleHr()
                            lgr.info('\t Finally! Fuzz testing  WRITE_SINGLE_REGISTER  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_SINGLE_REGISTER )


                        elif WRITE_MULTIPLE_COILS in fuzz_session.FCmergedlist :
                     
                            """Check that write WriteMultipleCoils queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 15 : WRITE_MULTIPLE_COILS .... ')
                            t.test_WriteMultipleCoils()
                            lgr.info('\t Finally! Fuzz testing  WRITE_MULTIPLE_COILS DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_MULTIPLE_COILS)
                            
                        
                        elif WRITE_MULTIPLE_REGISTERS in fuzz_session.FCmergedlist :

                            """Check that write WriteMultipleHr  queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 16 : WRITE_MULTIPLE_REGISTERS .... ')
                            t.test_WriteMultipleHr()
                            lgr.info('\t Finally!  Fuzz testing WRITE_MULTIPLE_REGISTERS  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_MULTIPLE_REGISTERS)
                                                  
                            """ the request is new function from pymodbus 1.3.2"""                  

                        elif Read_File_record in fuzz_session.FCmergedlist :

                            """Check that Read_File_record queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 20 : Read_File_record .... ')
                            t.test_ReadFileRecordRequestEncode()
                            lgr.info('\t Finally!  Fuzz testing  Read_File_record  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(Read_File_record)
                            

                        elif Write_File_record in fuzz_session.FCmergedlist :      

                            """Check that Write_File_record queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 21 : Write_File_record .... ')
                            t.test_WriteFileRecordRequestEncode()
                            lgr.info('\t Finally!  Fuzz testing  Write_File_record   DONE !!.' )
                            fuzz_session.FCmergedlist.remove(Write_File_record )
                            
                              
                        elif Mask_Write_Register in fuzz_session.FCmergedlist :      

                            """Check that Mask_Write_Register queries are handled correctly"""
                            lgr.info(''); lgr.info('\t Fuzzing  FC 22 : Mask_Write_Register .... ')
                            t.test_MaskWriteRegisterRequestEncode()
                            lgr.info('\t Finally! Fuzz testing  Mask_Write_Register DONE !!.' )
                            fuzz_session.FCmergedlist.remove(Mask_Write_Register)
                            
                              
                        elif Read_Write_Multiple_Registers in fuzz_session.FCmergedlist :      

                            """Check that Read_Write_Multiple_Registers are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 23 : Read_Write_Multiple_Registers .... ')
                            t.test_ReadWriteMultipleRegistersRequest()
                            lgr.info('\t Finally! Fuzz testing  Read_Write_Multiple_Registers !!.' )
                            fuzz_session.FCmergedlist.remove(Read_Write_Multiple_Registers)
                            
                  
                        elif Read_FIFO_queue in fuzz_session.FCmergedlist :  

                            """Check that ReadFifoQueueRequestEncode queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 24 : Read_FIFO_queue  .... ')
                            t.test_ReadFifoQueueRequestEncode()
                            lgr.info('\t Finally! Fuzz testing  Read_FIFO_queue  DONE !!.')
                            fuzz_session.FCmergedlist.remove(Read_FIFO_queue)

                        elif Read_device_Identification in fuzz_session.FCmergedlist :  

                            """Check ReadDeviceInformationRequest queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 43 : Read Device Identification interface  .... ')
                            t.test_Read_Device_Information()
                            lgr.info('\t Finally! Fuzz testing  Read Device Identification   DONE !!.')
                            fuzz_session.FCmergedlist.remove(Read_device_Identification)    
                        #----------------------------------------------------------------------------  
                        # Serial  FC                               
                        #---------------------------------------------------------------------------
                        elif Read_Exception_Status in fuzz_session.FCmergedlist :  
                            
                            """Check that Read_Exception_Statusqueries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 7 : Read_Exception_Status  .... ')                          
                            tsf.test_ReadExceptionStatus()
                            lgr.info('\t Finally!  Fuzz testing Read_Exception_Status DONE !!.')
                            fuzz_session.FCmergedlist.remove(Read_Exception_Status)

                        elif Get_Comm_Event_Counter in fuzz_session.FCmergedlist :  
                            
                            """Check that Get_Comm_Event_Counter are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 11 : Get_Comm_Event_Counter  .... ')                            
                            tsf.test_GetCommEventCounter()
                            lgr.info('\t Finally! Fuzz testing  Get_Comm_Event_Counter DONE !!.')
                            fuzz_session.FCmergedlist.remove(Get_Comm_Event_Counter)
                        
                        elif Get_Comm_Event_Logs in fuzz_session.FCmergedlist :  
                          
                            """Check Get_Comm_Event_Logs queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 12 : Get_Comm_Event_Logs  .... ')
                            tsf.test_GetCommEventLog()
                            lgr.info('\t Finally! Fuzz testing  Get_Comm_Event_Logs DONE !!.')
                            fuzz_session.FCmergedlist.remove(Get_Comm_Event_Logs)

                        elif Report_Slave_Id in fuzz_session.FCmergedlist :  
                          
                            """Check Report_Slave_Id queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 17 : Report_Slave_Id  .... ')                            
                            tsf.test_ReportSlaveId()
                            lgr.info('\t Finally! Fuzz testing  Report_Slave_Id !!.')
                            fuzz_session.FCmergedlist.remove(Report_Slave_Id)
              
                        elif Diagnostics in fuzz_session.FCmergedlist :
                            
                            lgr.info('')
                            lgr.info('\t Fuzzing  FC 8 : Diagnostics  .... ')
                            tsf.test_DiagnosticRequests()                            
                            #Testing diagnostic request messages for all sub_function_code and data field (0,65535)
                            #in case test PDU fields 2-way
                            if fuzz_session.flag_test_FC08_pair==True:
                            	tsf.test_DiagnosticRequests_data_field()
                            	fuzz_session.flag_test_FC08_pair=False                           
                            lgr.info('\t Finally! Fuzz testing  Diagnostics  !.')                            
                            fuzz_session.FCmergedlist.remove(Diagnostics)       
                        
                        else :                           
                            lgr.info('Error/Empty/not fuzzing FClist : %s' %fuzz_session.FCmergedlist)                                                                             
                            break

                    except modbus_b.ModbusError, ex:                           
                           lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
                           pass                                                                                                                                                                                                     
                           
                    #e.g connection refuse,broken pipe,reset by peer -loop and try recv() again new connection ,                                                                                                                                                                                     
                    except socket.error as socketerror:                                                                                                                                                                        
                           lgr.error("Socket Error: %s ", (socketerror))
                           time.sleep(1.0)
                           sys.exc_clear()
                           if  (socketerror.errno==errno.ECONNRESET or socketerror.errno==errno.EPIPE):                              
                               lgr.critical('Connection reset ...EPIPE..') ;pass                                         
                           elif socketerror.errno==errno.ECONNREFUSED : 
                               lgr.critical('Connection refused ......');self.recon_do_work(ever=True)                 
                                                                             
                           elif socketerror.errno == errno.ECONNABORTED: #add 06.04.20
                               lgr.critical('ECONNABORTED ......');pass
                           elif socketerror.errno == errno.EWOULDBLOCK:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                               lgr.critical('EWOULDBLOCK......');pass
                           elif (socketerror.errno  == errno.ENETRESET) or (socketerror.errno  == errno.ETIMEDOUT):
                                lgr.critical('Connection reset ....ENETRESET .. ETIMEDOUT))  ..') ;pass  

                           else:
                               sys.exc_clear()
                               lgr.error('Socket not response... disconnection, it can timeout processing/freeze/close')                           
                               time.sleep(1.0)
                               if socketerror.errno== errno.ECONNREFUSED: 
                                   lgr.critical('Connection refused ......'); self.recon_do_work(ever=True)               
                                              
                               
                               else :
                                   if fuzz_session.socket_flag==False :
                                        fuzz_session.stimeout=1 #first time, count t out ,counter   10
                                        fuzz_session.socket_flag=True #enable counter
                                        print ('\n\t  fuzz_session.stimeout------>',fuzz_session.stimeout)
                                        fuzz_session.num=fuzz_session.num_of_request
                                            
                                   #i already have a measurement, i look if it is continuous, socket_flag==False
                                   elif (fuzz_session.num_of_request-1 == fuzz_session.num) and (fuzz_session.stimeout!=10):                                   
                                        fuzz_session.stimeout += 1
                                        fuzz_session.num=fuzz_session.num_of_request
                                        if (fuzz_session.stimeout==10) :
                                            lgr.info('')
                                            lgr.critical('Connection it lost after %d request..Socket connect failed!'%fuzz_session.stimeout)
                                            fuzz_session.stimeout=0
                                            fuzz_session.socket_flag=False;self.recon_do_work(ever=True)
                                            time.sleep(1.0)
                                   else:
                                        fuzz_session.socket_flag=False
                                        fuzz_session.num=0                            
                    #default for detect error                                                                  
                    except:                                                                                      
                           
                           lgr.error('Other  err, exit and try creating socket again')
                           traceback.print_exc()                  
                           time.sleep(1.0)
                           pass  #debug break
                                                                                                                                                                                                                             
                lgr.info("Finally! . Fuzzer all DONE !!.")
                master1.close()                                


class TestQueriesSerialFC(SetupAndTeardown):
    '''
    This is the test for the pymodbus.diag_message module for Serial/Diagnostics FC
    Diagnostics FC This is the test for the pymodbus.diag_message module for Diagnostics FC
    Diagnostic Function Codes Base Classes diagnostic 08, 00-18,20
    --GetClearModbusPlusResponse, Returns a series of 54 16-bit words (108 bytes) in the data field
    of the response (this function differs from the usual two-byte
    length of the data field). The data contains the statistics for
    the Modbus Plus peer processor in the slave device.

    '''
    def __init__(self):

        self.illegal_pdu_len=[]
        self.start_data=0
        self.step_data=255
        self.end_data=65536
        
    diagnostics= [       
        
        (ReturnQueryDataRequest,                        '\x08\x00\x00\x00\x00'),
        (RestartCommunicationsOptionRequest,            '\x08\x00\x01\x00\x00'),# live the log but priot restart
        #(RestartCommunicationsclearRequest,             '\x08\x00\x01\xff\x00'),            
        (ReturnDiagnosticRegisterRequest,               '\x08\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterRequest,              '\x08\x00\x03\x00\x00'),
        (ForceListenOnlyModeRequest,                    '\x08\x00\x04'),
        (ClearCountersRequest,                          '\x08\x00\x0a\x00\x00'),
        (ReturnBusMessageCountRequest,                  '\x08\x00\x0b\x00\x00'),
        (ReturnBusCommunicationErrorCountRequest,       '\x08\x00\x0c\x00\x00'),
        (ReturnBusExceptionErrorCountRequest,           '\x08\x00\x0d\x00\x00'),
        (ReturnSlaveMessageCountRequest,                '\x08\x00\x0e\x00\x00'),
        (ReturnSlaveNoResponseCountRequest,             '\x08\x00\x0f\x00\x00'),
        (ReturnSlaveNAKCountRequest,                    '\x08\x00\x10\x00\x00'),
        (ReturnSlaveBusyCountRequest,                   '\x08\x00\x11\x00\x00'),
        (ReturnSlaveBusCharacterOverrunCountRequest,    '\x08\x00\x12\x00\x00'),
        (ReturnIopOverrunCountRequest,                  '\x08\x00\x13\x00\x00'),
        (ClearOverrunCountRequest,                      '\x08\x00\x14\x00\x00'),
        (GetClearModbusPlusRequest,                     '\x08\x00\x15\x00\x03'), # GetClearModbusPlus/(Get Statistics) 
        (RestartCommunicationsOptionRequest,            '\x08\x00\x01\xff\x00'), # Com Event Log clear
        (GetClearModbusPlusRequest,                     '\x08\x00\x15\x00\x04'), # GetClearModbusPlus/((Clear Statistics))         
    ]                                                                                   
    

    requests = [
        
        (RestartCommunicationsOptionRequest,            '\x00\x01\x00\x00', '\x00\x01\xff\x00'),
        (ReturnDiagnosticRegisterRequest,               '\x00\x02\x00\x00', '\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterRequest,              '\x00\x03\x00\x00', '\x00\x03\x00\x00'),
        (ForceListenOnlyModeRequest,                    '\x00\x04\x00\x00', '\x00\x04'),
        (ReturnQueryDataRequest,                        '\x00\x00\x00\x00', '\x00\x00\x00\x00'),
        (ClearCountersRequest,                          '\x00\x0a\x00\x00', '\x00\x0a\x00\x00'),
        (ReturnBusMessageCountRequest,                  '\x00\x0b\x00\x00', '\x00\x0b\x00\x00'),
        (ReturnBusCommunicationErrorCountRequest,       '\x00\x0c\x00\x00', '\x00\x0c\x00\x00'),
        (ReturnBusExceptionErrorCountRequest,           '\x00\x0d\x00\x00', '\x00\x0d\x00\x00'),
        (ReturnSlaveMessageCountRequest,                '\x00\x0e\x00\x00', '\x00\x0e\x00\x00'),
        (ReturnSlaveNoResponseCountRequest,             '\x00\x0f\x00\x00', '\x00\x0f\x00\x00'),  
        (ReturnSlaveNAKCountRequest,                    '\x00\x10\x00\x00', '\x00\x10\x00\x00'),
        (ReturnSlaveBusyCountRequest,                   '\x00\x11\x00\x00', '\x00\x11\x00\x00'),
        (ReturnSlaveBusCharacterOverrunCountRequest,    '\x00\x12\x00\x00', '\x00\x12\x00\x00'),
        (ReturnIopOverrunCountRequest,                  '\x00\x13\x00\x00', '\x00\x13\x00\x00'),
        (ClearOverrunCountRequest,                      '\x00\x14\x00\x00', '\x00\x14\x00\x00'),
        (GetClearModbusPlusRequest,                     '\x00\x15\x00\x00', '\x00\x15' + '\x00\x00' * 55),
    ]

    responses = [
        
        (ReturnQueryDataResponse,                      '\x00\x00\x00\x00'),
        (RestartCommunicationsOptionResponse,          '\x00\x01\x00\x00'),
        (ReturnDiagnosticRegisterResponse,             '\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterResponse,            '\x00\x03\x00\x00'),
        (ForceListenOnlyModeResponse,                  '\x00\x04'),
        (ReturnQueryDataResponse,                      '\x00\x00\x00\x00'),
        (ClearCountersResponse,                        '\x00\x0a\x00\x00'),
        (ReturnBusMessageCountResponse,                '\x00\x0b\x00\x00'),
        (ReturnBusCommunicationErrorCountResponse,     '\x00\x0c\x00\x00'),
        (ReturnBusExceptionErrorCountResponse,         '\x00\x0d\x00\x00'),
        (ReturnSlaveMessageCountResponse,              '\x00\x0e\x00\x00'),
        (ReturnSlaveNoReponseCountResponse,            '\x00\x0f\x00\x00'),
        (ReturnSlaveNAKCountResponse,                  '\x00\x10\x00\x00'),
        (ReturnSlaveBusyCountResponse,                 '\x00\x11\x00\x00'),
        (ReturnSlaveBusCharacterOverrunCountResponse,  '\x00\x12\x00\x00'),
        (ReturnIopOverrunCountResponse,                '\x00\x13\x00\x00'),
        (ClearOverrunCountResponse,                    '\x00\x14\x00\x00'),
        (GetClearModbusPlusResponse,                   '\x00\x15' + '\x00\x00' * 55),
    ]

    
    def print_results(self,**kwargs): 
        
        print >>sys.stderr,  '                                                                              '                                                                             
        for name, value in kwargs.items():
            print '{0} = {1}'.format(name, value)
        print >>sys.stderr,   '                                                                              '                                                                              
        return       
    #------------------------------------------------------------------------------------#    
    # """ Looking for some  diagnostics for recon""" -not use same recon
    #------------------------------------------------------------------------------------#  
    def reconise_diagnostics(self):    
        """ Looking for some  diagnostics for reconiss """
        
        lgr.info('\n \t \t \t ........send  diagnostics..')    
        for msg, enc in self.diagnostics:
            lgr.info('Diagnostics msg : ----->%s ' % msg)
            response_pdu=master1.execute_master(slave,enc)
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))         
        return 

    
    #not use -Looking for supported diagnostics subcodes..      
    def getSupportedsubcodesDiagnostics(self):
        """Looking for supported diagnostics subcodes.."""

        supportedsubDiagnostics = []
        lgr.info('\n \t \t \t ...Looking for supported diagnostics subcodes..') 
        for i in range(21,65535,self.step_data):      
            pdu="\x08"+struct.pack(">H",i)+"\x00\x00"
            response=master1.execute_fpdu(slave,pdu)                                       #return  to tumple
                                                                       
            """analyze the received data Response message analyzer""" 
            if len(response) >= 2 :                                                       # and len(response[0]) > 1 and response[0][1]:
            #if response:
                return_code=response[0]
                exceptionCode=response[1]
                              
                if return_code >= 128 or exceptionCode == 1 or exceptionCode == 3 or exceptionCode == 4:                 
                    lgr.warn("Sub Diagnostics Code=%r not supported" % (str(i)))
                    #print "Sub Diagnostics Code "+str(i)+" not supported."
                    
                else:
                    supportedsubDiagnostics.append(i)
                    lgr.warn("Sub Diagnostics Code=%r is supported" % (str(i)))
            else:
                lgr.warn("Sub Diagnostics Code=%r probably supported" % (str(i)))
                supportedsubDiagnostics.append(i)

        lgr.info ( '\n----------------supportedsubDiagnostics  --------------')
        self.print_results(response=supportedsubDiagnostics)
        return      

    #---------------------------------------------------- Serial FC -----------------------------------------------#
     
    #07 (0x07) Read Exception Status (Serial Line only) .
    #This function code is used to read the contents of eight Exception Status outputs in a remote device.  
    #The function provides a simple method for
    #accessing this information, because the Exception Output references are known (no output reference is needed in the function).
         
    #---------------------------------------------------------------------------------------------------------------#
    def test_ReadExceptionStatus(self):
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
        
            handle  = ReadExceptionStatusRequest()            
            result = struct.pack(">B",Read_Exception_Status)+handle.encode()
            response=master1.execute_fpdu(slave,result) 
            lgr.info('answer >>  Output data: %s'  % (response,))

        fuzz_session.flag_reguest=True     
                
    
    #'''
    #11 (0x0B) Get Comm Event Counter (Serial Line only)
    #This function code is used to get a status word and an event count from
    #the remote device's communication event counter.
    #By fetching the current count before and after a series of messages, a client can determine whether the messages were handled normally by the
    #remote device.
    #The device's event counter is incremented once  for each successful message completion. It is not incremented for exception responses,
    #poll commands, or fetch event counter commands.
    #The event counter can be reset by means of the Diagnostics function (code 08), with a subfunction of Restart Communications Option
    #(code 00 01) or Clear Counters and Diagnostic Register (code 00 0A)
    #'''
    def test_GetCommEventCounter(self):
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
            handle  = GetCommEventCounterRequest()           
            result = struct.pack(">B",Get_Comm_Event_Counter)+handle.encode()
            response=master1.execute_fpdu(slave,result)
            lgr.info('Answer >>  response %s'  % (response, ))

        fuzz_session.flag_reguest=True      
       
        """
        12 (0x0C) Get Comm Event Log (Serial Line only)  
        #This function code is used to get a status word, event count, message count, and a field of event bytes from the remote device.
        #The status word and event counts are identical to that returned by the Get Communications
        #Event Counter function (11, 0B hex). The message counter contains the quantity of messages processed by the remote device
        #since its last restart, clear counters operation, or power–up. This count is identical to that
        #returned by the Diagnostic function (code 08), sub-function Return Bus Message Count (code 11, 0B hex).
        #The event bytes field contains 0-64 bytes, with each byte corresponding to the status of one
        #MODBUS send or receive operation for the remote device. The remote device enters the events into the field in chronological order. 
        #Byte 0 is the most recent event. Each new byte flushes the oldest byte from the field.
        """
    def test_GetCommEventLog(self):
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
            handle  = GetCommEventLogRequest()
            result = struct.pack(">B",Get_Comm_Event_Logs)+handle.encode()
            response=master1.execute_fpdu(slave,result)
            lgr.info('Answer >>  response %s'  % (response, ))
        fuzz_session.flag_reguest=True
         
        """ 17 (0x11) Report Server ID (Serial Line only) 
           This function code is used to read the description of the type, the current status, and other information specific to a remote device.
        """
    def test_ReportSlaveId(self):
        
        for a in itertools.count():
            if fuzz_session.flag_reguest==False :
                break
            handle = ReportSlaveIdRequest()
            result = struct.pack(">B",Report_Slave_Id)+handle.encode()
            response=master1.execute_fpdu(slave,result)
            lgr.info('Answer >>  response %s'  % (response, ))
        fuzz_session.flag_reguest=True    

    def test_DiagnosticRequests_data_field(self):
        '''
        This is the test for the pymodbus.diag_message module, for Diagnostics FC
        Testing diagnostic request messages for all sub_function_code and data field (0,65535)
        >> use in 2-way test subfunction vs data !!!! in case t 3 test PDU fields
        use step prodefine --
        self.start_data=0
        self.step_data=255
        self.end_data=65535
        '''
        for a in itertools.count(): 
            
            for msg,enc in self.diagnostics :
                
                ''' Diagnostic Sub Code 00'''
            
                if msg==ReturnQueryDataRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-00 : ReturnQueryDataRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data,self.step_data))
                    
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ReturnQueryDataRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))
                                                                                                                               
                
                ''' Diagnostic Sub Code 01 '''
                       
                if msg==RestartCommunicationsOptionRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-01 : RestartCommunicationsOptionRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = RestartCommunicationsOptionRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                    
                
                ''' Diagnostic Sub Code 02 '''  

                if msg==ReturnDiagnosticRegisterResponse:
                    lgr.info('\n \t \t \t  Fuzzing  FC 08-02 : ReturnDiagnosticRegisterRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ReturnDiagnosticRegisterRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response==""or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                ''' Diagnostic Sub Code 03 '''
                       
                if msg==ChangeAsciiInputDelimiterRequest:
                    lgr.info('\n \t \t \t   Fuzzing  FC 08-03 : ChangeAsciiInputDelimiterRequest  .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ChangeAsciiInputDelimiterRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                   
                
                ''' Diagnostic Sub Code 04 '''
                         
                if msg==ForceListenOnlyModeRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-04 : ForceListenOnlyModeRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                  
                        handle  = ForceListenOnlyModeRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                ''' Diagnostic Sub Code 10 '''
                         
                if msg==ClearCountersRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-10 : ClearCountersRequest  ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                    
                        handle  = ClearCountersRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                             
                
                ''' Diagnostic Sub Code 11 '''
                          
                if msg==ReturnBusMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-11 : ReturnBusMessageCountRequest  .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ReturnBusMessageCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                ''' Diagnostic Sub Code 12 '''
                        
                if msg==ReturnBusCommunicationErrorCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-12 : ReturnBusCommunicationErrorCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                   
                        handle  = ReturnBusCommunicationErrorCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        #lgr.info('Answer >>  response %r'  % (response, ))
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                
                
                ''' Diagnostic Sub Code 13 '''
                        
                if msg==ReturnBusExceptionErrorCountRequest:
                    lgr.info('\n \t \t\t Fuzzing  FC 08-13 : ReturnBusExceptionErrorCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                        
                        handle  = ReturnBusExceptionErrorCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                            
                
                ''' Diagnostic Sub Code 14 '''
                          
                if msg==ReturnSlaveMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-14 : ReturnSlaveMessageCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                   
                        handle  = ReturnSlaveMessageCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                             
                
                ''' Diagnostic Sub Code 15 '''
                
                if msg==ReturnSlaveNoResponseCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-15 : ReturnSlaveNoResponseCountRequest ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):               
                        handle  = ReturnSlaveNoResponseCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                            
               
                ''' Diagnostic Sub Code 16 ''' 
                         
                if msg==ReturnSlaveNAKCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-16 : ReturnSlaveNAKCountRequest ....start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                    
                        handle  = ReturnSlaveNAKCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        #print >>sys.stderr, 'response %r' % (response,) 
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))
                                                     
                
                '''  Diagnostic Sub Code 17 ''' 
                      
                if msg==ReturnSlaveBusyCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-17 : ReturnSlaveBusyCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):
                        handle  = ReturnSlaveNAKCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                           

                '''  Diagnostic Sub Code 18  ''' 
                         
                if msg==ReturnSlaveBusCharacterOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-18 : ReturnSlaveBusCharacterOverrunCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ReturnSlaveBusCharacterOverrunCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                    
                
                '''  Diagnostic Sub Code 19 ''' 
                         
                if msg==ReturnIopOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-19 : ReturnIopOverrunCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ReturnIopOverrunCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                                  
                
                '''  Diagnostic Sub Code 20  ''' 
                          
                if msg==ClearOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-20 : ClearOverrunCountRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = ClearOverrunCountRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))                                                 
                '''
                 Diagnostic Sub Code 21                                sub function code = 0x0015
                '\x08\x00\x15\x00\x03'),                               GetClearModbusPlus/(Get Statistics)     
                '\x08\x00\x15\x00\x04'),                               GetClearModbusPlus/((Clear Statistics)) 
                '''         
                if msg==GetClearModbusPlusRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-21 : GetClearModbusPlusRequest .... start_data %d, end_data, %d step_data %d' %(self.start_data,self.end_data ,self.step_data))
                    for a in range(self.start_data,self.end_data,self.step_data):                
                        handle  = GetClearModbusPlusRequest(a)
                        result = struct.pack(">B",Diagnostics)+handle.encode()
                        response=master1.execute_fpdu(slave,result)
                        if response=="" or len(response)==1:
                            lgr.warn('Answer >>  response %r test data %r ' % (response,ByteToHex(struct.pack(">H",a))))
                        else :
                            lgr.info('Answer >>  response %r'  % (response, ))

                    break
            break                 
        fuzz_session.flag_reguest=False        
        lgr.info('Done sub_function_code and data field test ')        
        sleep(1.0)                                                    
        return         


    def test_DiagnosticRequests(self):
        '''
        This is the test for the pymodbus.diag_message module, for Diagnostics FC
        Testing diagnostic request messages for all sub_function_code and data field 
        '''
        for a in itertools.count():
            
            for msg,enc in self.diagnostics:
                ''' Diagnostic Sub Code 00'''
            
                if msg==ReturnQueryDataRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-00 : ReturnQueryDataRequest  ....init')
                    handle  = ReturnQueryDataRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break               
                
                ''' Diagnostic Sub Code 01 '''
                       
                if msg==RestartCommunicationsOptionRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-01 : RestartCommunicationsOptionRequest  ....init')
                    handle  = RestartCommunicationsOptionRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                       lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                       lgr.info('Answer >>  response %r'  % (response, ))                
                    if fuzz_session.flag_reguest==False :
                        break
                 
                
                ''' Diagnostic Sub Code 02 '''  

                if msg==ReturnDiagnosticRegisterRequest:
                    lgr.info('\n \t \t \t  Fuzzing  FC 08-02 : ReturnDiagnosticRegisterRequest  ....init ')                   
                    handle  = ReturnDiagnosticRegisterRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break                     
                 
                
                ''' Diagnostic Sub Code 03 '''
                       
                if msg==ChangeAsciiInputDelimiterRequest:
                    lgr.info('\n \t \t \t   Fuzzing  FC 08-03 : ChangeAsciiInputDelimiterRequest  .... init')
                    
                    handle  = ChangeAsciiInputDelimiterRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                  
                    if fuzz_session.flag_reguest==False :
                        break                
                
                ''' Diagnostic Sub Code 04 '''
                         
                if msg==ForceListenOnlyModeRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-04 : ForceListenOnlyModeRequest  ....init')                       
                    handle  = ForceListenOnlyModeRequest(a)
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result) 
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break                     
                
                ''' Diagnostic Sub Code 10 '''
                         
                if msg==ClearCountersRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-10 : ClearCountersRequest  ....init')                       
                    handle = ClearCountersRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)                   
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))

                    if fuzz_session.flag_reguest==False :
                        break
                    
                
                ''' Diagnostic Sub Code 11 '''
                          
                if msg==ReturnBusMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-11 : ReturnBusMessageCountRequest  .... init ')
                    handle  = ReturnBusMessageCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break
                    
                ''' Diagnostic Sub Code 12 '''
                        
                if msg==ReturnBusCommunicationErrorCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-12 : ReturnBusCommunicationErrorCountRequest .... init')
                    
                    handle  = ReturnBusCommunicationErrorCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
               
                    if fuzz_session.flag_reguest==False :
                        break
                    
               
                ''' Diagnostic Sub Code 13 '''
                        
                if msg==ReturnBusExceptionErrorCountRequest:
                    lgr.info('\n \t \t\t Fuzzing  FC 08-13 : ReturnBusExceptionErrorCountRequest .... init')
                       
                    handle  = ReturnBusExceptionErrorCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                          
                
                ''' Diagnostic Sub Code 14 '''
                          
                if msg==ReturnSlaveMessageCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-14 : ReturnSlaveMessageCountRequest .... init')                                  
                    handle  = ReturnSlaveMessageCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                           
                
                """ Diagnostic Sub Code 15"""
                        
                if msg==ReturnSlaveNoResponseCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-15 : ReturnSlaveNoResponseCountRequest ....init')                    
                    handle  = ReturnSlaveNoResponseCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))                    
                    if fuzz_session.flag_reguest==False :
                        break                         
               
                ''' Diagnostic Sub Code 16 ''' 
                         
                if msg==ReturnSlaveNAKCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-16 : ReturnSlaveNAKCountRequest ....init')
                    handle  = ReturnSlaveNAKCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                            break                     
                
                '''  Diagnostic Sub Code 17 ''' 
                      
                if msg==ReturnSlaveBusyCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-17 : ReturnSlaveBusyCountRequest .... init')                    
                    handle  = ReturnSlaveNAKCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                            break                     

                
                '''  Diagnostic Sub Code 18  ''' 
                         
                if msg==ReturnSlaveBusCharacterOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-18 : ReturnSlaveBusCharacterOverrunCountRequest .... init')
                    handle  = ReturnSlaveBusCharacterOverrunCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                    
                
                '''  Diagnostic Sub Code 19 ''' 
                         
                if msg==ReturnIopOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-19 : ReturnIopOverrunCountRequest .... ')
                    
                    handle  = ReturnIopOverrunCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                    
                
                '''  Diagnostic Sub Code 20  ''' 
                          
                if msg==ClearOverrunCountRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-20 : ClearOverrunCountRequest .... ')                                        
                    handle  = ClearOverrunCountRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break                         
                '''
                 Diagnostic Sub Code 21                                sub function code = 0x0015
                '\x08\x00\x15\x00\x03'),                               GetClearModbusPlus/(Get Statistics)     
                '\x08\x00\x15\x00\x04'),                               GetClearModbusPlus/((Clear Statistics)) 
                '''         
                if msg==GetClearModbusPlusRequest:
                    lgr.info('\n \t \t \t Fuzzing  FC 08-21 : GetClearModbusPlusRequest .... ')
                    handle  = GetClearModbusPlusRequest()
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    if response=="" or len(response)==1:
                        lgr.warn('Answer >>  response %r' % (response, ))
                    else :
                        lgr.info('Answer >>  response %r'  % (response, ))
                    if fuzz_session.flag_reguest==False :
                        break
            
            if fuzz_session.flag_reguest==False :
                        break             
        fuzz_session.flag_reguest=True        
        lgr.info('Empty Diagnostic Sub Code ')
        sleep(1.0)                                                    
        return        
#----------------------------------------------------------------------------#  
#This class fuzz testing  a field of PDU Modbus protocol
#cross  pairs parameter of FC 
#----------------------------------------------------------------------------#
class fuzzer_pdu():    
    
    all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
    
    def __init__(self ):
        
        """Constructor. Set the Initializing settings
           public_codes={1-64, 73-99, 111-127},User_defined codes=ranges {65-72, 100-110}
           exeption_codes interesting value 128_to_255

         """         
        
        self.public_codes=[i for j in (range(0,65), range(72,100),xrange(110,128)) for i in j]
        self.User_defined_codes=[i for j in ((range(64,73), range(99,111))) for i in j]
        self.exeption_codes=list_of_fuzz().lib_interesting_128_to_255()
        self.output_value=1

    
    def print_results(self,**kwargs): 
        
        print >>sys.stderr,  '                                                                              '                                                                             
        for name, value in kwargs.items():
            print '{0} = {1}'.format(name, value)
        print >>sys.stderr,   '                                                                              '                                                                              
        return   

   
    
    def reset_coverage(self):
        '''
        This function  return list of use class coverage 

        '''             
        fuzz_session.tmp_test_list=[]
        fuzz_session.rows_of_cover=[]

    def reset(self):
        '''
        This function  return list of use coverage and flag for fuzzing PDU
        fuzz_session.rows_of_cover=[]-- return list of use class coverage 

        '''        
        fuzz_session.tmp_list_of_case=[]
        fuzz_session.fields_of_list=[]
        fuzz_session.tmp_test_list=[]
        fuzz_session.rows_of_cover=[]

        fuzz_session.test_flag_parameter_PDU=True    #end test parameter_PDU
        fuzz_session.test_flag_fc=True               #disable/enable test FC for next FC
        fuzz_session.flag_reguest=False              #Stop reguest /and fuzzer  
   
    def test_field_of_data(self,len_of_data): 
       '''
       This function  return replace a heuristic  length  valid or invalid for intersesting value or random 
       one char for field of data 
       len_of_data is test 0f N byte to
       send data len of random string /ascii/all char/only alpanum/only one char
       '''
       f_of_data=""
       r=random.randint(0,100)
       #fuzz_random ='char'
       lgr.info('Fuzz test field of data, len_of_data : %d'% len_of_data)
     
       if r>35:                                                                      
            lgr.info('all char')
            f_of_data= ''.join([chr(random.randint(0,255)) for i in xrange(0,len_of_data)]) 
       elif r>70:                                         
            lgr.info('ascii only')
            f_of_data= ''.join([chr(random.randint(0,128)) for i in xrange(0,len_of_data)])
       elif r>80:     
            lgr.info('only alpanummeric')
            f_of_data= ''.join([chr((random.randint(0,96))+32) for i in xrange(0,len_of_data)])                               
       else:                                            
            c=random.randint(0,96)+32           
            lgr.info('patterns one char : %r , 0x%02X ' % (c,c))
            f_of_data = ''.join( [chr(c) for i in xrange(0,len_of_data)])           
       lgr.info('data_testing_field .. to 260 HexByte: %r' % ByteToHex(f_of_data [:260]))
       return f_of_data
            
    def is_valid_combination( self,values, names,start_address=None,max_address=None):

        """ example as FC43  PAIRWISE test

            rules Allpairs
            Read Device ID code                      Object Name
            DeviceInformation_Basic:  0x01,         range [0x00 -0x02]    
            DeviceInformation_Regular= 0x02 ,       range [0x03 -0x7F]
            DeviceInformation_Extended= 0x03 ,      range [0x80–0xFF] 
            DeviceInformation_Specific= 0x04 , 
        """
        dictionary = dict( zip( names, values ) )

        rules = [ 
                lambda d: 1 == d["Read Dev Id code"] and d[0<="Object_Id"<3]  
                ,lambda d: 2 == d["Read Dev Id code"] and d[3<="Object_Id"<129]
                ,lambda d: 3 == d["Read Dev Id code"] and d[128<"Object_Id"<256]
                   
                ]
            
        for rule in rules:
                try:
                    if rule(dictionary):
                        return False
                except KeyError: pass
                return True

    def pair(self,parameters,function_code):

        """ PAIRWISE test -create of NIST-ACST as e.g FC43_pair_test.csv
            or create of tools AllPairs 2.0.1 
        """

        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        lgr.info("PAIRWISE list Initializes")
        try:
        
            if os.path.exists("FC%d_pair.csv"%function_code):
                # read CSV file & load into list
                with open("FC%d_pair.csv"%function_code,'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to Init
                    pairwise = list(map(lambda line: [int(x) for x in line],pairwise_temp))
            else:
                    pairwise=list(all_pairs(
                    [x[1] for x in parameters],
                    filter_func=lambda values: self.is_valid_combination_FC01(
                        values, [x[0] for x in parameters])))

                    pairwise.sort(key = lambda row: row[1])
            
        except IOError :
            lgr.exception('')

        if not pairwise:
            raise ValueError ('no data')    
        

        lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise))
        return np.array(pairwise)

    #----------------------------------------------------------------------------------------------------#            
    #  PAIRWISE  test for FC 43         
    #----------------------------------------------------------------------------------------------------# 
    def is_valid_combination_FC43( self,values, names,start_address=None,max_address=None):

        """ 
        FC43  PAIRWISE test
        Read Device ID code                     Object Name
        DeviceInformation_Basic:  0x01,         range [0x00 -0x02]    
        DeviceInformation_Regular= 0x02 ,       range [0x03 -0x7F]
        DeviceInformation_Extended= 0x03 ,      range [0x80–0xFF] 
        DeviceInformation_Specific= 0x04 ,
         ------------------------"Contr." ..rules-----#excludes them 
         lambda d: 1 == d["Read Dev Id code"]!=1 --single test
        ,lambda d: 2 == d["Read Dev Id code"] and d[3<="Object_Id"<129]
        ,lambda d: 3 == d["Read Dev Id code"] and d[128<"Object_Id"<256]
                
        """
        dictionary = dict( zip( names, values ) )

        rules = [ 
                 lambda d: 1 == d["Read Dev Id code"]!=1 
                 ,lambda d: 2 == d["Read Dev Id code"] and d[3<="Object_Id"<129]
                 ,lambda d: 3 == d["Read Dev Id code"] and d[128<"Object_Id"<256]
                   
                ]
            
        for rule in rules:
            try:
                if rule(dictionary):
                    return False
            except KeyError: pass
        return True

    def FC43_pairwise(self,parameters,function_code,dir='./Nist-csv'):

        """ PAIRWISE test for FC43  -create of NIST-ACST as FC43_pair_test.csv-defaults
            or create of tools AllPairs 2.0.1
        ACTS Test Suite Generation: Wed Mar 18 20:43:59 EET 2020/ -CSV FILE
        *' represents don't care value -extend test all pairwise for mei_type=x0E
        and some test for mei_type=0,1,2,..127,128..254..255
        Test case Initializing
        Test case Initializing  mei_type: 0,255,13,14
        Test case Initializing Read Dev Id code: 60 case
        Test case Initializing Object_Id: 60 case

        all case mei_type:14 and compinatorial Read Dev Id code and Object_Id, ex 60 test with
        coverage single test with Read Dev Id code:1
        and 100 case for mei_type:13, 0, 255 and compinatorial Read Dev Id code and Object_Id:
        Test case Initializing : ..3880
        .//Nist-csv ..
        ......

        for All pair tools 
        all case mei_type:14 and compinatorial Read Dev Id code and Object_Id
        Test case Initializing  mei_type: 1  (only value 14 x0E)
        Test case Initializing Read Dev Id code: 60
        Test case Initializing Object_Id: 60
        PAIRWISE list Initializes
        Test case Initializing : ..3600-60=3540

        """

        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        lgr.info("PAIRWISE list Initializes")
        
        try:
            if os.path.exists(dir+"/FC%d_pair.csv"%function_code):           
                # read CSV file & load into list
                with open(dir+"/FC%d_pair.csv"%function_code,'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to Init
                    pairwise = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))                            
            else:
                    lgr.info("------- not file NIST-ACTS, use AllPairs tools ..")
                    pairwise=list(all_pairs(
                    [x[1] for x in parameters],
                    filter_func=lambda values: self.is_valid_combination_FC43(
                        values, [x[0] for x in parameters])))

                    pairwise.sort(key = lambda row: (row[1],row[2]))
            
                    #save in root /dir temporary
                    with open("FC%d_pair.csv"%function_code,"w") as f:
                        wr = csv.writer(f)
                        wr.writerows(pairwise)
        except IOError : 
              lgr.info("------- not file NIST-ACTS or use AllPairs tools ..")
              raise     
        
        if len(pairwise)==0:
            raise ValueError ('no data') 

        lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise))
        return np.array(pairwise)     

    
    def is_valid_combination_f16( self,values, names, start_address=None,max_address=None):

        """
        Quantity of Registers :2 Bytes (0x0001 to 0x007B)
        Byte Count :1 Byte (2 x N*)
        Registers Value : N* x 2 Bytes value
        ------------------------"Contr." ..rules-----#excludes them  
        lambda d: d["byte_count"] == 2*d["quantity"] and d["num_values"] == 2*d["quantity"]
        lambda d: d["num_values"] % 2 == 0 
        see, dir utils for script python
        """
        dictionary = dict( zip( names, values ) )

        rules = [ 
                lambda d: d["byte_count"] == 2*d["quantity"] and d["num_values"] == 2*d["quantity"],
                lambda d: d["num_values"] % 2 == 0                           
                ]           
        for rule in rules:
            try:
                if rule(dictionary):
                    return False
            except KeyError: pass
        return True
    
    #----------------------------------------------------------------------------------------------------#            
    # PAIRWISE  test for FC 16  
    # ACTS Test Suite Generation
    # ACTS Test Suite Generation: Wed Mar 18 21:01:10 EET 2020
    #  '*' represents don't care value 
    # Degree of interaction coverage: 2
    # Number of parameters: 3
    # Maximum number of values per parameter: 165
    # Number of configurations: 13122

    # quan,byte_count,num_value

    # for All pair tools 
    # test case Initializing quantity: 165
    # Test case Initializing byte_count: 60
    # Test case Initializing num_values: 183
    # PAIRWISE list Initializes
    # Test case Initializing : 15840
    
    #----------------------------------------------------------------------------------------------------#

    def FC16_pairwice_Quant_byte_count(self,FC16_parameters,dir='./Nist-csv'):
        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        pairwise_temp =[]
       
        lgr.info("case 2 PAIRWISE list Initializes Combinatorial(Quantity of Registers, byte_count, num of value)")
        try:        
            if os.path.exists(dir+"/FC16_pair.csv"):#demo test
                # read CSV file & load into list
                with open(dir+"/FC16_pair.csv", 'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwise = list(map(lambda line: [int(x) for x in line],pairwise_temp))
              
            else:
                    lgr.info("Not file NIST-ACTS, Initializing with tools All_pairs  .. and write PAIRWISE np array ..")
                    pairwise=list(all_pairs(
                    [x[1] for x in FC16_parameters],
                    filter_func=lambda values: self.is_valid_combination_f16
                        (values, [x[0] for x in FC16_parameters])))
                        
                    pairwise.sort(key = lambda row: row[0])           
                    with open("FC16_pair.csv","w") as f:
                        wr = csv.writer(f)
                        wr.writerows(pairwise)
        except IOError :
            lgr.exception('')

        if not pairwise:
            raise ValueError ('no data')           

        lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise))

        return np.array(pairwise)    

    #----------------------------------------------------------------------------------------------------#            
    # PAIRWISE  test for FC 15  
    # ACTS Test Suite Generation
    # num number of values per parameter: 130
    # Number of configurations: 
    # quan,byte_count,num_value
    #Test case Initializing : 15380

    # for All pair tools 
    # Test case Initializing quantity: 130
    # Test case Initializing byte_count: 60
    # Test case Initializing num_values: 183
    # PAIRWISE list Initializes
    # Test case Initializing : 15380
    
    #----------------------------------------------------------------------------------------------------#
    def FC15_pairwice_Quant_byte_count(self,FC15_parameters, start_address,max_address,dir='./Nist-csv'):
        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        lgr.info("case 2 PAIRWISE list Initializes Combinatorial (Quantity of coils, byte_count, output_value)")
        try:  
            if os.path.exists(dir+"/FC15_pair.csv"):
                # read CSV file & load in  list
                with open(dir+"/FC15_pair.csv", 'r') as f:
                    lgr.info("Read PAIRWISE list ..")
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwise=list(map(lambda line: [int(x) for x in line],pairwise_temp))
                    
            else:
                    lgr.info("Initializing with tools all_pairs  .... and write PAIRWISE np array ..")
                    pairwise=list(all_pairs(
                    [x[1] for x in FC15_parameters],
                    filter_func=lambda values: self.is_valid_combination_f15(
                        values, [x[0] for x in FC15_parameters])))
                    pairwise.sort(key = lambda row: row[0])       
                    with open("FC15_pair.csv","w") as f:
                        wr = csv.writer(f)
                        wr.writerows(pairwise)
        except IOError :
            lgr.exception('')

        if not pairwise:
            raise ValueError ('no data')   


        lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise))

        return np.array(pairwise)        

    def is_valid_combination_f15( self,values, names, start_address=0,max_address=1024):

        """
        Quantity of Registers :2 Bytes (0 , 1968)
        Byte Count :1 Byte 
        Coils Value : N* x 1 Bytes value
        Byte Count == Quantity of Outputs % 8 + [Quantity of Outputs / 8]
        and Outputs Value ==Quantity of Outputs/8
        [[Constraint]--#excludes them
        -- this section is also optional
        num_value!=quan/8
        byte_count != (quan%8 )+ (quan / 8)
        """
        dictionary = dict( zip( names, values ) )

        rules = [ 
                lambda d: d["byte_count"] == (d["quantity"]%8 + d["quantity"] / 8)                             
                ,lambda d: d["num_values"] == d["quantity"]/8                             
                ]
            
        for rule in rules:
            try:
                if rule(dictionary):
                    return False
            except KeyError: pass
        return True

    #-----------------------------------------------------------------------------------------------------#            
    #  PAIRWISE  test for FC 23 
    # ACTS Test Suite Generation--dir='./Nist-csv'
    #ACTS Test Suite Generation: Wed Mar 18 21:14:49 EET 2020
    #  '*' represents don't care value 
    # Degree of interaction coverage: 2
    # Number of parameters: 3
    # Maximum number of values per parameter: 165
    # Number of configurations: 12397
    # quan,byte_count,num_value

    # for All pair tools 
    # test case Initializing quantity: 165
    # Test case Initializing byte_count: 60
    # Test case Initializing num_values: 165
    # PAIRWISE list Initializes
    # Test case Initializing : 14190
           
    #-----------------------------------------------------------------------------------------------------#
    def FC23_pairwice_Quant_byte_count(self,FC23_parameters,dir='./Nist-csv'):
        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        lgr.info("PAIRWISE list Initializes")
        try:

            if os.path.exists(dir+"/FC23_pair.csv"):
                # read CSV file & load into list
                with open(dir+"/FC23_pair.csv", 'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwise = list(map(lambda line: [int(x) for x in line],pairwise_temp))              
            else:
                    pairwise=list(all_pairs(   
                    [x[1] for x in FC23_parameters],
                    filter_func=lambda values: self.is_valid_combination_f23(
                        values, [x[0] for x in FC23_parameters])))

                    pairwise.sort(key = lambda row: row[0])           
                    with open("FC23_pair.csv","w") as f:
                        wr = csv.writer(f)
                        wr.writerows(pairwise)

        except IOError :
            lgr.exception('')
            raise

        if len(pairwise)==0:
            raise ValueError ('no data')    
                        
        lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise))

        return np.array(pairwise)        

    def is_valid_combination_f23( self,values, names):

        """
        Quantity to Read 2 Bytes 0x0001 to 0x007D
        Write Starting Address 2 Bytes 0x0000 to 0xFFFF
        Quantity to Write 2 Bytes 0x0001 to 0X0079
        Write Byte Count 1 Byte 2 x N*
        Write Registers Value N*x 2 Bytes  

        "Contr." ..rules--
        lambda d: d["byte_count"] == 2*d["quantity_write"] and d["num_value"] == 2*d["quantity_write"]                         
        ,lambda d: d["num_value"] % 2 == 0]

        """
        dictionary = dict( zip( names, values ) )

        rules = [ 
                lambda d: d["byte_count"] == 2*d["quantity_write"] and d["num_value"] == 2*d["quantity_write"]                         
                ,lambda d: d["num_value"] % 2 == 0
                ]
            
        for rule in rules:
            try:
                if rule(dictionary):
                    return False
            except KeyError: pass
        return True
             
    def fuzz_field_parameter_FC01(self,function_code,pdu):

        """ i) testing single field address  ii) coil quantity - under conditions all oter field not change
            fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
            calculate fuzz quantity_of_x  for FC from class list_of_fuzz   
            pack bits in bytes
            byte_count = quantity_of_x / 8 -if (quantity_of_x % 8) > 0: byte_count += 1 
            iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /tmp
            iv)coverage case valid invalid value from address, quan ,and  address_and_quantity 
            case and coverage for field no:
            e.g
            address        2000       63536      100.00
            quantity_of_x  2000       63536      100.00
           
           self.reset() intialize temp list and flag
           fuzz_session.test_flag_parameter_PDU=False   #end test parameter_PDU
           fuzz_session.test_flag_fc=True              #disable/enable test FC for next FC
           fuzz_session.flag_reguest=False              #Stop reguest /and fuzzer  
        """
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field % r ' % test_field)
               
        if test_field=='address' :                                                    
            starting_address=fuzz_session.fuzz_addre_COILS[0]
            fuzz_session.fuzz_addre_COILS.append(fuzz_session.fuzz_addre_COILS.pop(0))                        #shift a list
        
        elif test_field=='quantity_of_x' :          
            quantity_of_x= fuzz_session.quantity_of_x_list_coil[0]
            fuzz_session.quantity_of_x_list_coil.append(fuzz_session.quantity_of_x_list_coil.pop(0))           #shift a list
        
        elif test_field=='2-way':  
            starting_address,quantity_of_x= self.fuzz_field_two_way_FC01(function_code,pdu)
            
        else :
            lgr.info('error')    

        if starting_address <fuzz_session.MIN_COILS or starting_address>fuzz_session.MAX_COILS:
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1

        if quantity_of_x>2000 or quantity_of_x==0:
            lgr.warn('Coils quantity invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Coils quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1

        if (starting_address+quantity_of_x) > fuzz_session.MAX_COILS :
            lgr.warn('(address + quantity) is invalid : %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1            
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1
            fuzz_session.flag_boundaries=0 
            
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x])
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_COILS) or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_COILS):
            
            if test_field=='address': 
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535)         
               
            if test_field=='quantity_of_x':                             
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535)         
           
            #l.insert(newindex, l.pop(oldindex))
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]           
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))            
                               
        elif (len(pairwice_READ_COILS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=65535) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            #intialize temp list of list for coverage  and flag
            self.reset()
           
        fuzz_session.starting_address=starting_address;fuzz_session.quantity_of_x=quantity_of_x        
        return   struct.pack(">BHH", function_code, starting_address, quantity_of_x)


    def fuzz_field_two_way_FC01(self,function_code,pdu,dir="./tmp"):

        """cross product pairs OF COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
           integer_boundaries for byte count REG: quantity_of_x_list
           use csv file from heuristic class findPairs for  FC for interest  value or cartesian product use min.max address (reconise) and interest value from 
           pairwice_READ_COILS is np array
           parameters= [ ( "address"
           fuzz_session.fuzz_addre_COILS_cart)
          , ( "quantity"
           , fuzz_session.quantity_of_x_list_coil_cart)
             ]
        """
        global  slave,pairwice_READ_COILS

        if  len(pairwice_READ_COILS)==0 :
            lgr.info('--------------------------Test case Initializing from CSV or Cartesian product  -------------------------------------------\n')     
            lgr.info("---------Csv file Initializes ")
            if os.path.exists(dir+"/FC01_pair.csv"):
                # read CSV file & load in  list
                with open(dir+"/FC01_pair.csv", 'r') as f:
                    lgr.info("---------Read csv file .....")
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwice_READ_COILS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))                    
            else:
                    lgr.warn("------------not file heuristic CSV, Use cartesian list..of interesting value ..")
                    #pairwice_READ_COILS=self.findPairs(fuzz_session.fuzz_addre_COILS_cart, fuzz_session.quantity_of_x_list_coil_cart,fuzz_session.MAX_COILS )
                    pairwice_READ_COILS=np.array(list(itertools.product(fuzz_session.fuzz_addre_COILS_cart,fuzz_session.quantity_of_x_list_coil_cart)))
                    
                    with open(dir+"/FC01_pair.csv","w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table ../tmp.")
                        wr.writerows(pairwice_READ_COILS)
                          
            lgr.info('--------- Test case Initializing --------- : %d '% len(pairwice_READ_COILS ))

        starting_address=pairwice_READ_COILS[0][0]
        quantity_of_x=pairwice_READ_COILS[0][1]            
        pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)
        return starting_address,quantity_of_x
       

    def fuzz_field_parameter_FC02(self,function_code,pdu):

        """ i) testing single field address  ii) Discrete inputs quantity - under conditions all oter field not change
            fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
            calculate fuzz value quantity_of_x, address  from class -list_of_fuzz
            iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /tmp
            iv)coverage case valid invalid value from address, quan ,and  address_and_quantity              
        """
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        test_field = fuzz_session.test_field_read_fc[0]
       
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field % r ' % test_field)
           
        if test_field=='address' :                                                     
            starting_address=fuzz_session.fuzz_addre_DIS_IN[0]
            fuzz_session.fuzz_addre_DIS_IN.append(fuzz_session.fuzz_addre_DIS_IN.pop(0))                      #shift a list
        
        elif test_field=='quantity_of_x' :            
            quantity_of_x= fuzz_session.quantity_of_x_list_coil[0]
            fuzz_session.quantity_of_x_list_coil.append(fuzz_session.quantity_of_x_list_coil.pop(0))           #shift a list
          
        elif test_field=='2-way':  
            starting_address,quantity_of_x=self.fuzz_field_two_way_FC02(function_code,pdu)
        
        else :
            lgr.info('error')    

        if (starting_address <fuzz_session.MIN_DIS_IN) or (starting_address>fuzz_session.MAX_DIS_IN):
           lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
           fuzz_session.field1_invalid += 1
           
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1
        
        if quantity_of_x >2000 or quantity_of_x==0:
            lgr.warn('DISCRETE_INPUTS quantity invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
            

        else :
            lgr.info('DISCRETE_INPUTS valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1
            fuzz_session.flag_boundaries=0   
        
        if (starting_address+quantity_of_x) > fuzz_session.MAX_DIS_IN :            
            lgr.warn('(address + quantity) is invalid : %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1   
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1 
        
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x])
        
         #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_DIS_IN) or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_COILS):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535)            
                                          
            if test_field=='quantity_of_x':                                                        
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535)            
        
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]             
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) 
        
        elif (len(pairwice_READ_DISCRETE_INPUTS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=65535)           
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            self.reset()
                              
        fuzz_session.starting_address=starting_address;fuzz_session.quantity_of_x=quantity_of_x                       
        return struct.pack(">BHH", function_code, starting_address, quantity_of_x)  

    
    def fuzz_field_two_way_FC02(self,function_code,pdu,dir="./tmp"):
        """
        Test case Initializing   -Csv file rom heuristic class findPairs
        pairwice_READ_DISCRETE_INPUTS numpy array
        """
        
        global  slave,pairwice_READ_DISCRETE_INPUTS
        
        if  len(pairwice_READ_DISCRETE_INPUTS)==0 :
            lgr.info('--------------------------Test case Initializing from CSV or Cartesian product  -------------------------------------------\n')
            if os.path.exists(dir+"/FC02_pair.csv"):
                # read CSV file & load in  list
                with open(dir+"/FC02_pair.csv", 'r') as f:
                    lgr.info("---------Read csv file ....")
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwice_READ_DISCRETE_INPUTS =np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                    
            else:
                    lgr.info("-----------not file heuristic CSV, use cartesian list..of interesting value  ..")
                    pairwice_READ_DISCRETE_INPUTS=np.array(list(itertools.product(fuzz_session.fuzz_addre_DIS_IN_cart,fuzz_session.quantity_of_x_list_coil_cart)))    
                    
                    with open(dir+"./FC02_pair.csv","w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table .../tmp")
                        wr.writerows(pairwice_READ_DISCRETE_INPUTS)

            lgr.info('--------- Test case Initializing --------- : %d '% len(pairwice_READ_DISCRETE_INPUTS))

        starting_address=pairwice_READ_DISCRETE_INPUTS[0][0]       
        quantity_of_x=pairwice_READ_DISCRETE_INPUTS[0][1]
        pairwice_READ_DISCRETE_INPUTS=np.delete(pairwice_READ_DISCRETE_INPUTS, 0, 0)
        
        return starting_address,quantity_of_x    
    
    def fuzz_field_parameter_FC03(self,function_code,pdu):
        
        """  
            i) testing single field address  ii) register quantity - under conditions all other field not change
            fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
            calculate fuzz quantity_of_x  for FC from class list_of_fuzz 
            iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /tmp
            iv)coverage case valid invalid value from address, quan ,and  address_and_quantity
           
        """
        #global tmp_test_list,fuzz_session.fields_of_list,tmp_list_of_case
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field % r ' % test_field)
                
        if test_field=='address' :                                      
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))                     #shift a list
        
        elif test_field=='quantity_of_x' :
            quantity_of_x= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))           #shift a list
           
        elif test_field=='2-way':
            starting_address,quantity_of_x=self.fuzz_field_two_way_FC03(function_code,pdu)  
            
        else :
            lgr.info('error')    
                
        if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
           lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
           fuzz_session.field1_invalid += 1
           
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1

        if quantity_of_x >125 or quantity_of_x==0:
            lgr.warn('READ_HOLDING_REGISTERS invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
            
        else :
            lgr.info('READ_HOLDING_REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1  
        
        if (starting_address+quantity_of_x) > fuzz_session.MAX_HO_REG :
            lgr.warn('(address + quantity) is invalid : %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1  
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1
            fuzz_session.flag_boundaries=0 
       
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x])
        
        #check -fuzz_session.l_fuzz_addre_register,fuzz_session.l_quantity_of_register last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_HO_REG) or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_REG):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) 

        elif (len(pairwice_READ_HOLDING_REGISTERS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=65535) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            self.reset()
           
        fuzz_session.starting_address=starting_address
        fuzz_session.quantity_of_x=quantity_of_x 
        return   struct.pack(">BHH", function_code, starting_address, quantity_of_x)    


    def fuzz_field_two_way_FC03(self,function_code,pdu,dir="./tmp"):       
        """
        Test case Initializing  Cartesian product or NIST-ACTS-Csv file 
        numpy array pairwice_READ_HOLDING_REGISTERS
        """

        global  slave,pairwice_READ_HOLDING_REGISTERS
 
        if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
            lgr.info('--------------------------Test case Initializing from CSV or Cartesian product  -------------------------------------------\n')
            lgr.info(" ---------Csv file Initializes")
            if os.path.exists(dir+"/FC03_pair.csv"):
                # read CSV file & load in  list
                with open(dir+"/FC03_pair.csv", 'r') as f:
                    lgr.info("---------Read csv file .. ..")
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwice_READ_HOLDING_REGISTERS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                    
            else:
                    lgr.info("------------not file heuristic CSV, Use cartesian list..of interesting value ..")
                    pairwice_READ_HOLDING_REGISTERS=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart)))

                    with open(dir+"/FC03_pair.csv","w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table .../tmp")
                        wr.writerows(pairwice_READ_HOLDING_REGISTERS)
     
            lgr.info('--------- Test case Initializing --------- : %d '% len(pairwice_READ_HOLDING_REGISTERS))

        starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
        quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
        pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)

        return starting_address,quantity_of_x

    def fuzz_field_parameter_FC04(self,function_code,pdu):
        """
         i)testing single field address  ii) coil quantity - under conditions all oter field not change
            fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
            calculate fuzz quantity_of_x  for FC from class list_of_fuzz
            iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /tmp
            iv)coverage case valid invalid value from address, quan ,and  address_and_quantity  
        """
        fuzz_session.flag_boundaries=0
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field % r ' % test_field)
                 
        if test_field=='address' :                                       
            starting_address=fuzz_session.fuzz_addre_IN_REG[0]
            fuzz_session.fuzz_addre_IN_REG.append(fuzz_session.fuzz_addre_IN_REG.pop(0))                     #shift a list
        
        elif test_field=='quantity_of_x' :
            quantity_of_x= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))           #shift a list
           
        elif test_field=='2-way':  
            starting_address,quantity_of_x=self.fuzz_field_two_way_FC04(function_code,pdu)
                   
        else :
            lgr.info('error')    
 
        if (starting_address <fuzz_session.MIN_IN_REG) or (starting_address>fuzz_session.MAX_IN_REG):
           lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
           fuzz_session.field1_invalid += 1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1
     
        if (quantity_of_x >125 or quantity_of_x==0):
            lgr.warn('READ_INPUT_REGISTERS quantity invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('READ_INPUT_REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1  
        
        if (starting_address+quantity_of_x) > fuzz_session.MAX_IN_REG:
            lgr.warn('(address + quantity) is invalid : %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1        
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1 
            
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x])
        
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_IN_REG ) or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_REG):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_test_list)
            fuzz_session.tmp_test_list=[]
            
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) 
                               
        elif (len(pairwice_READ_INPUT_REGISTERS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=65535) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            self.reset()
           
        fuzz_session.starting_address=starting_address
        fuzz_session.quantity_of_x=quantity_of_x      
        return struct.pack(">BHH", function_code, starting_address,quantity_of_x)

    
    def fuzz_field_two_way_FC04(self,function_code,pdu,dir="./tmp"):

        """Test case Initializing  Cartesian product"""

        global  slave,pairwice_READ_INPUT_REGISTERS
 
        if  len(pairwice_READ_INPUT_REGISTERS)==0 :
            lgr.info('--------------------------Test case Initializing from CSV or Cartesian product  -------------------------------------------\n')
            lgr.info("---------Csv file Initializes")
            if os.path.exists(dir+"/FC04_pair.csv"):
                # read CSV file & load in  list
                with open(dir+"/FC04_pair.csv", 'r') as f:
                    lgr.info("---------Read csv file .. ..")
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise_temp))

                    pairwice_READ_INPUT_REGISTERS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                    
            else:
                    lgr.info("-----------not file heuristic CSV, use cartesian list..of interesting value  ..")                    
                    pairwice_READ_INPUT_REGISTERS=np.array(list(itertools.product(fuzz_session.fuzz_addre_IN_REG_cart,fuzz_session.quantity_of_x_list_reg_cart)))
                    
                    with open(dir+"/FC04_pair.csv","w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table ../tmp")
                        lgr.info('--------------------------------------------------------------------------------------------\n')
                        wr.writerows(pairwice_READ_INPUT_REGISTERS)

            lgr.info('--------- Test case Initializing --------- : %d '% len(pairwice_READ_INPUT_REGISTERS ))

        starting_address=pairwice_READ_INPUT_REGISTERS[0][0]
        quantity_of_x=pairwice_READ_INPUT_REGISTERS[0][1]
             
        pairwice_READ_INPUT_REGISTERS=np.delete(pairwice_READ_INPUT_REGISTERS, 0, 0)
        return starting_address,quantity_of_x
    
    def fuzz_field_parameter_FC05(self,function_code,pdu):
        """
         i) testing single field address and ii) output_value  - under conditions all oter field not change 
        fuzz_session.test_field_write_fc=['address', 'output_value', '2-way']
        iii) test 2-way, files for NIST-ACTS as csv include in folder root mtf
        iv)coverage case valid invalid value from address, output_value 
           
        """
        global pairwice_WRITE_SINGLE_COIL
        fuzz_session.flag_boundaries=0             
        starting_address,output_value = struct.unpack(">HH", pdu[1:5])
        tcc=test_case_coverage()
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_write_fc[:]
       
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field  % r ' % test_field)
                 
        if test_field=='address' :                                     
            starting_address=fuzz_session.fuzz_addre_COILS[0]
            fuzz_session.fuzz_addre_COILS.append(fuzz_session.fuzz_addre_COILS.pop(0))   #shift a list
            
        elif test_field=='output_value' :
            output_value= fuzz_session.values_test[0]
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))           #shift a list
       
        elif test_field=='2-way':              
            starting_address,output_value =self.fuzz_field_two_way_FC05(function_code,pdu)
             
        else :
            lgr.info('error')

        #check address    
        if (starting_address <fuzz_session.MIN_COILS) or (starting_address>fuzz_session.MAX_COILS):
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
            fuzz_session.flag_boundaries=1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1
            #fuzz_session.flag_boundaries=0
        
        #check value 
        if (output_value ==0) or (output_value==65280 ):
            lgr.info('output_value valid : %d ..0x%02X ..' % (output_value,output_value))
            fuzz_session.field2_valid += 1                     
        else :
            lgr.warn('output_value invalid: %d ..0x%02X ..' % (output_value,output_value))
            fuzz_session.field2_invalid += 1
            fuzz_session.flag_boundaries=1 
                    
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,output_value])
        
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_COILS) or (test_field=='output_value' and output_value==fuzz_session.l_output_value):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_write_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,fuzz_session.tmp_test_list)
            fuzz_session.tmp_test_list=[]            
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) 

        elif (len(pairwice_WRITE_SINGLE_COIL)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list))
            self.reset()
                        
        fuzz_session.starting_address=starting_address
        fuzz_session.output_value=output_value     
        return  struct.pack(">BHH", function_code, starting_address,output_value)
    
    def fuzz_field_two_way_FC05(self,function_code,pdu):
        """
        Test case Initializing  Cartesian product
        np.array(itertools.product(a, b))
        Cartesian product of x and y array points into single array of 2D points
        directly initialize 
        x= np.array([], dtype=np.init) such x= pairwice_WRITE_SINGLE_COIL           
      	 x = numpy.delete(x, (0), axis=0)
      	negatve integer library.The bit field a number of variable length word_binary
        """

        global  slave,lib_word_cart,pairwice_WRITE_SINGLE_COIL 
        lib_word=list_of_fuzz().lib_word_cart()
        if  len(pairwice_WRITE_SINGLE_COIL)==0 :
            pairwice_WRITE_SINGLE_COIL=np.array(list(itertools.product(fuzz_session.fuzz_addre_COILS_cart,lib_word)))       
        fuzz_session.starting_address=pairwice_WRITE_SINGLE_COIL[0][0]
        #negatve integer library.The bit field a number of variable length word_binary                                                                           
        value=bit_field((int(pairwice_WRITE_SINGLE_COIL[0][1])),16,65535, "<","ascii",signed=False).render()   #string                                
        pairwice_WRITE_SINGLE_COIL=np.delete(pairwice_WRITE_SINGLE_COIL, 0, 0)               
        return  fuzz_session.starting_address,int(value)

    def fuzz_field_parameter_FC06(self,function_code,pdu):
        """ 
        i) testing single field address and ii) output_value  - under conditions all oter field not change 
        fuzz_session.test_field_write_fc=['address', 'output_value', '2-way']
        iii) test 2-way, files for NIST-ACTS as csv include in folder root mtf
        iv)coverage case valid invalid value from address, output_value 
        fuzz_session.test_field_write_fc=['address', 'output_value', '2-way'] 
           
        """
        fuzz_session.flag_boundaries=0        
        starting_address,output_value = struct.unpack(">HH", pdu[1:5])
        tcc=test_case_coverage()
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_write_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field  % r ' % test_field)
           
        if test_field=='address' :                                     
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))   #shift a list
            
        elif test_field=='output_value' :
            output_value= fuzz_session.values_test[0]
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))                #shift a list        
        #
        elif test_field=='2-way':  
            starting_address,output_value=self.fuzz_field_two_way_FC06(function_code,pdu)
           
        else :
            lgr.info('error')

        #check address  and value 
        if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
            fuzz_session.flag_boundaries=1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1
        
        #check value -all value valid
        lgr.info('Output value: %d ...0x%02X ..' % (output_value,output_value))
        fuzz_session.field2_valid += 1  
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,output_value])
        
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_HO_REG) or (test_field=='output_value' and output_value==fuzz_session.l_output_value):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_write_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
                        
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) 

        elif (len(pairwice_WRITE_SINGLE_REGISTER)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quantity ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list))
            self.reset()
                          
        fuzz_session.starting_address=starting_address
        fuzz_session.output_value=output_value     
        return  struct.pack(">BHH", function_code, starting_address,output_value)

    def fuzz_field_two_way_FC06(self,function_code,pdu):
        """ 
        Test case Initializing  Cartesian product (fuzz_addre_HO_REG_cart x )
        np.array(itertools.product(a, b))
        Cartesian product of x and y array points into single array of 2D points
        directly initialize 
        x= np.array([], dtype=np.init) such x= pairwice_WRITE_SINGLE_REGISTER
        for i in range(0, rows):
           for j in range(0, cols):
        print a[i,j]
        np.delete(arr, 0, 0)
        a = np.array([])
        if a.size == 0:
  	    x = numpy.delete(x, (0), axis=0)
  	    negatve integer library.The bit field a number of variable length word_binary
        """
        
        global  slave,lib_word_cart,pairwice_WRITE_SINGLE_REGISTER        
        lib_word=list_of_fuzz().lib_word_cart()
        if pairwice_WRITE_SINGLE_REGISTER.size==0 :                
            pairwice_WRITE_SINGLE_REGISTER=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,lib_word)) )
  
        fuzz_session.starting_address=pairwice_WRITE_SINGLE_REGISTER[0][0]                                                                         
        value=bit_field((int(pairwice_WRITE_SINGLE_REGISTER[0][1])),16,65535, "<","ascii",signed=False).render() #string            
        pairwice_WRITE_SINGLE_REGISTER=np.delete(pairwice_WRITE_SINGLE_REGISTER, 0, 0)
        return  fuzz_session.starting_address,int(value)   

    def fuzz_field_parameter_FC15(self,function_code,pdu,output_value=None,case_FC15=None):
        """ 
        i) testing one-way field in list global  fuzz_session.test_field_mult_fc
        fuzz_session.test_field_mult_fc=['address', 'quantity_of_x','byte_count','output_value', '2-way'] 
        fuzz_session.quantity_of_x_list_coil or fuzz_session.quantity_of_x_list_reg  
        in def Read_CSvFile
        fuzz_session.flag_boundaries=0, default
        
        """
        tcc=test_case_coverage()
        fuzz_session.flag_boundaries=0       
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:]
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_mult_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field % r ' % test_field)

        if test_field=='address' :                                        
            starting_address=fuzz_session.fuzz_addre_COILS[0]
            fuzz_session.fuzz_addre_COILS.append(fuzz_session.fuzz_addre_COILS.pop(0))                    #shift a list
        
        elif test_field=='quantity_of_x' :           
            quantity_of_x= fuzz_session.quantity_of_x_list_coil[0]
            fuzz_session.quantity_of_x_list_coil.append(fuzz_session.quantity_of_x_list_coil.pop(0))       #shift a list
        
        elif test_field=='byte_count' : 
            byte_count=fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))  
        
        elif test_field=='output_value' :                  #add 11.11.18 check in spec len 
            #output_value=fuzz_session.output_value_test[0]
            output_value =self.test_field_of_data(fuzz_session.output_value_test[0])   # OUTPUT byte seq
            fuzz_session.output_value_test.append(fuzz_session.output_value_test.pop(0)) 

        #2-way test   
        elif test_field=='2-way':
            return self.fuzz_field_two_way_FC15(function_code,pdu,output_value=None,case_FC15=None)   
                        
        else :
            lgr.info('error')

        if starting_address <fuzz_session.MIN_COILS or starting_address>fuzz_session.MAX_COILS:
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1

        if quantity_of_x>1968 or quantity_of_x==0:
            lgr.warn('Coils quantity invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Coils quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1

        if (starting_address+quantity_of_x) > fuzz_session.MAX_COILS :
            lgr.warn('(address + quantity) is invalid : %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1   
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1
            fuzz_session.flag_boundaries=0 

        if (byte_count >1968/8) or (byte_count==0):                   
            lgr.warn('Coils byte_count invalid: %d ..0x%02X ..' % (byte_count,byte_count ))
            fuzz_session.field3_invalid += 1
        else :
            lgr.info('Coils byte_count valid: %d ..0x%02X ..' % (byte_count,byte_count ))
            fuzz_session.field3_valid += 1

        if (len(output_value)>0 or (len(output_value))<=246):                  #output_value=241, max N * byte for len 260 packet
            lgr.info('output_ data len  valid: %d ..0x%02X ..' % (len(output_value),len(output_value)))
            fuzz_session.field4_valid += 1  
        else :
            lgr.warn('output_data len invalid: %d..0x%02X ..' % (len(output_value),len(output_value)))
            fuzz_session.field4_invalid += 1          
    
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
        
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_COILS)  \
        or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_COILS)  \
        or (test_field=='byte_count' and byte_count==fuzz_session.l_count_byte_test)\
        or (test_field=='output_value' and (len(output_value))==fuzz_session.l_output_value_test):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='byte_count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=256) 
            
            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            tcc.test_case (function_code,test_field,fuzz_session.test_field_mult_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
                       
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))                
    
        fuzz_session.starting_address=starting_address
        fuzz_session.quantity_of_x=quantity_of_x
        fuzz_session.byte_count=byte_count

        pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x,byte_count)
        pdu +=output_value 
        return   pdu

    def fuzz_field_two_way_FC15(self,function_code,pdu,output_value=None,case_FC15=None,dir="./tmp"):
        
        """
        Test case Initializing Cartesian product case 1
        case 1, cross product pairs OF COILS, and integer_boundaries for byte count coil: quantity_of_x_list
        case 2, (Combinatorial) Quantity of coils (0x0001 to 0x07B0) vs byte_count (N*) N = Quantity of out/8, vs output_value=N*x1B
        pairwice_Quant_vs_byte_count=np.array([], dtype=np.int16)
        pairwice_READ_COILS=np.array([], dtype=np.int16)
        
        """
        global  slave,lib_word_binary,pairwice_READ_COILS,pairwice_Quant_vs_byte_count
        tcc=test_case_coverage()
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:]; case_FC15=fuzz_session.case_FC15
       
        while True:
            # case 1
            if case_FC15==True:
        
                if  pairwice_READ_COILS.size==0:
                   
                    if os.path.exists(dir+"/FC01_pair.csv"):
                        # read CSV file & load in  list
                        with open(dir+"/FC01_pair.csv", 'r') as f:
                            lgr.info("Read csv file .. ..")
                            reader = csv.reader(f)
                            pairwise_temp = list(reader)
                            #convert all elements to init
                            pairwice_READ_COILS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                            
                    else:
                            lgr.info("---------------not file NIST-ACTS, Cartesian list ..")
                            pairwice_READ_COILS=np.array(list(itertools.product(fuzz_session.fuzz_addre_COILS_cart,fuzz_session.quantity_of_x_list_coil_cart)))
     
                    
                    lgr.info('----------- case 1 cross product pairs of address COILS and integer_boundaries  quantity_of_x')
                    lgr.info('----------- case 1 num of test %d'%len(pairwice_READ_COILS))

                lgr.info('------- case 1 cross product, starting_address Quantity of coils')
                starting_address=pairwice_READ_COILS[0][0]
                              
                if starting_address <fuzz_session.MIN_COILS or starting_address>fuzz_session.MAX_COILS:
                    lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
                else :
                    lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))

                fuzz_session.quantity_of_x=pairwice_READ_COILS[0][1]
                
                if fuzz_session.quantity_of_x >1968 or fuzz_session.quantity_of_x==0:
                    lgr.warn('Coils write quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))

                else :
                    lgr.info('Coils write quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))    
                
                if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_COILS :
                    lgr.warn('(address + quantity write) is invalid : %d ..0x%02X ..' % (starting_address+fuzz_session.quantity_of_x,starting_address+fuzz_session.quantity_of_x))
                    fuzz_session.flag_boundaries=1
                else :  
                    lgr.info('(address + quantity write) is  valid: %d ..0x%02X ..' % (starting_address+fuzz_session.quantity_of_x,starting_address+fuzz_session.quantity_of_x))   
                    fuzz_session.flag_boundaries=0
                lgr.info('Byte_count: %d ..0x%02X ' % (byte_count,byte_count))
                lgr.info('len output_value: %d' % len(output_value))

                fuzz_session.starting_address=starting_address  
                pdu = struct.pack(">BHHB", function_code, starting_address, fuzz_session.quantity_of_x,byte_count)
                pdu +=output_value
                fuzz_session.tmp_test_list.append ([starting_address,fuzz_session.quantity_of_x,byte_count,len(output_value)])
                pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)
                
                if  len(pairwice_READ_COILS)==0 :
                    tcc.test_case (function_code,'address vs quantity',['address', 'quantity_of_x','byte_count','output_value'],np.array(fuzz_session.tmp_test_list))
                    fuzz_session.case_FC15=False
                    fuzz_session.tmp_test_list=[]       
                break
          
            elif fuzz_session.case_FC15==False:
                # byte_count,integer fuzz heuristics library  lib_interesting_256(),
                # output_value, fuzz heuristics library for illegal len frame 
                #
                parameters = [ ( "quantity"
                               , fuzz_session.quantity_of_x_list_coil_cart)
                             , ( "byte_count"
                               ,  list_of_fuzz().lib_interesting_256())
                               , ( "output_value"
                               ,fuzz_session.illegal_pdu_len )                                
                             ]
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    pairwice_Quant_vs_byte_count=self.FC15_pairwice_Quant_byte_count(parameters, start_address,fuzz_session.MAX_COILS)
                    
                    lgr.info('------- case 2 Quantity of coils (0x0001 to 0x07B0) vs byte_count (N*) vs output_value' )
                    lgr.info('case 2 num of test %d'%len(pairwice_Quant_vs_byte_count))
                
                lgr.info('------- case 2, Combinatorial (Quantity of coils, byte_count, output_value)' )    
                fuzz_session.quantity_of_x=pairwice_Quant_vs_byte_count[0][0]
                
                
                if fuzz_session.quantity_of_x >1968 or fuzz_session.quantity_of_x==0:
                   
                    lgr.warn('Coils write quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Coils write quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))    
                
                byte_count=pairwice_Quant_vs_byte_count[0][1]               
                
                if (byte_count >1968/8) or (byte_count==0):
                    
                    lgr.warn('Coils byte_count invalid: %d ..0x%02X ..' % (byte_count,byte_count ))
                else :
                    lgr.info('Coils byte_count valid: %d ..0x%02X ..' % (byte_count,byte_count )) 

                #output_value=tuple(self.COILS_quantity)*[self.output_value])    
                output_value=4*(pairwice_Quant_vs_byte_count[0][2])*[1,0]   #demo                  
                lgr.info('data value (bit): %d' %len(output_value))
                
                pdu = struct.pack(">BHHB", function_code, starting_address, fuzz_session.quantity_of_x,byte_count)
                #def execute from modbus.py
                i, byte_value = 0, 0
                for j in output_value:
                    if j > 0:
                        byte_value += pow(2, i)
                    if i == 7:
                        pdu += struct.pack(">B", byte_value)
                        i, byte_value = 0, 0
                    else:
                        i += 1
                if i > 0:
                    pdu += struct.pack(">B", byte_value)
                
                fuzz_session.starting_address=starting_address               
                fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
                pairwice_Quant_vs_byte_count=np.delete(pairwice_Quant_vs_byte_count, 0, 0)
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    tcc.test_case (function_code,'Quant_vs_byte_count_vs_value',['address', 'quantity_of_x','byte_count','output_value'],np.array(fuzz_session.tmp_test_list))                   
                    fuzz_session.case_FC15=True
                    self.reset()
                                                                                 
                break
            else :
                pass
        
        return pdu

    def fuzz_field_parameter_FC16(self,function_code,pdu,case_FC16=None,output_value=None):

        """
        i) testing one-way field in list global fuzz_session.test_field_mult_fc
            fuzz_session.test_field_mult_fc=['address', 'quantity_of_x','byte_count' '2-way'] 
            fuzz_session.quantity_of_x_list_coil or fuzz_session.quantity_of_x_list_reg  
            in def Read_CSvFile
        """
        #global tmp_test_list,fields_of_list,tmp_list_of_case   
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:]
        tcc=test_case_coverage()
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_mult_fc[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field  % r ' % test_field)
        
        if test_field=='address' :                                                    
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))                 #shift a list
        
        elif test_field=='quantity_of_x' :           
            quantity_of_x= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))       #shift a list
        
        elif test_field=='byte_count' : 
            byte_count= fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))  
        
        elif test_field=='output_value' :                  #add 11.11.18
            output_value =self.test_field_of_data(fuzz_session.output_value_test[0])
            fuzz_session.output_value_test.append(fuzz_session.output_value_test.pop(0))

        elif test_field=='2-way':
            return self.fuzz_field_two_way_FC16(function_code,pdu,case_FC16=None,output_value=None)
            
        else :
            lgr.info('error') 
        
        if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
            fuzz_session.flag_boundaries=1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1
            fuzz_session.flag_boundaries=0
        
        if quantity_of_x >123 or quantity_of_x==0:
            lgr.warn('Write HOLDING_REGISTERS quantity invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Write HOLDING_REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1
                
        if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_HO_REG :
            lgr.warn('(address + quantity) is invalid : %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1     
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1
            fuzz_session.flag_boundaries=0     
        
        if byte_count >2*123 or byte_count==0:
            lgr.warn('Write byte_count invalid: %d ....' % byte_count)
            fuzz_session.field3_invalid += 1
        else :
            lgr.info('Write byte_count valid: %d ....' % byte_count)
            fuzz_session.field3_valid += 1 

        if (output_value>246):                                 #output_value=246, max N * 2byte for len 260 packet
            lgr.info('output_ data len value invalid: %d ....' % len(output_value))
            fuzz_session.field4_invalid += 1  
        else :
            lgr.info('output_data len value valid: %d ....' % len(output_value))
            fuzz_session.field4_valid += 1

        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
        #check -fuzz_session.l_fuzz_addre_REG,fuzz_session.l_quantity_of_reg last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_HO_REG)  \
        or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_REG)  \
        or (test_field=='byte_count' and byte_count==fuzz_session.l_count_byte_test) \
        or (test_field=='output_value' and len(output_value)==fuzz_session.l_output_value_test):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='byte_count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=256) 
            
            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=256) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_mult_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]                        
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))  
        
        fuzz_session.starting_address=starting_address
        fuzz_session.quantity_of_x=quantity_of_x
        fuzz_session.byte_count=byte_count
        pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x,byte_count)
        pdu +=output_value 
        return  pdu
            
        
    def fuzz_field_two_way_FC16(self,function_code,pdu,case_FC16=None,output_value=None,dir="./tmp"):
        """
        Test case Initializing  Cartesian product
        case 1 cross product pairs of address HO_REG and integer_boundaries  quantity_of_x_list)
        case 2 Quantity of Registers (0x0001 to 0x007B) vs byte_count (2 x N*) N = Quantity of Registers,
        """
        global slave,pairwice_READ_HOLDING_REGISTERS,pairwice_Quant_vs_byte_count
        tcc=test_case_coverage()
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:]

        case_FC16=fuzz_session.case_FC16
        
        while True:
            # case 1
            if case_FC16==True:
               
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :                    
                    lgr.info("---------Csv file Initializes")
                    
                    if os.path.exists(dir+"/FC03_pair.csv"):
                        # read CSV file & load in  list
                        with open(dir+"/FC03_pair.csv", 'r') as f:
                            lgr.info("Read csv file .....")
                            reader = csv.reader(f)
                            pairwise_temp = list(reader)
                            #convert all elements to init
                            pairwice_READ_HOLDING_REGISTERS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                            
                    else:
                            lgr.info("not file CSV, Cartesian list ..")
                            pairwice_READ_HOLDING_REGISTERS=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart)))
                    
                    lgr.info('case 1 cross product pairs of address HO_REG and integer_boundaries  quantity_of_x_list')
                    lgr.info('case 1 total num of test %d'%len(pairwice_READ_HOLDING_REGISTERS))
                 
                lgr.info('case 1 cross product pairs of address HO_REG and integer_boundaries quantity_of_x')
                
                starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                               
                if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
                   
                   lgr.warn('address invalid: %d ..0x%02X..' % (starting_address,starting_address))
                   fuzz_session.flag_boundaries=1
                else :
                    lgr.info('address valid: %d ..0x%02X..' % (starting_address,starting_address))
                    fuzz_session.flag_boundaries=0

                quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                
                
                if fuzz_session.quantity_of_x >123 or fuzz_session.quantity_of_x==0:
                    
                    lgr.warn('Write_HOLDING_REGISTERS quantity invalid: %d ..0x%02X..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Write_HOLDING_REGISTERS quantity valid: %d ..0x%02X..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                        
                if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_HO_REG :
                    
                    lgr.warn('(address + quantity) is invalid : %d ..0x%02X..' % (starting_address+fuzz_session.quantity_of_x,starting_address+fuzz_session.quantity_of_x))
                    fuzz_session.flag_boundaries=1
                else :  
                    lgr.info('(address + quantity) is  valid: %d ..0x%02X..' % (starting_address+fuzz_session.quantity_of_x,starting_address+fuzz_session.quantity_of_x)) 
                    fuzz_session.flag_boundaries=0
               
                lgr.info(' byte_count: %d..0x%02X' % (byte_count,byte_count))
                lgr.info(' len output_value: %d' % len(output_value))
                fuzz_session.starting_address=starting_address      
                
                fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                               
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    #to case2
                    tcc.test_case (function_code,'address vs quantity',['address', 'quantity_of_x','byte_count','output_value'],np.array(fuzz_session.tmp_test_list))
                    fuzz_session.tmp_test_list=[]
                    fuzz_session.case_FC16=False                   
                break    

            # case 2
            #combinatorial parameter >> Quantity of Registers (0x0001 to 0x007B)
            # vs byte_count (2 x N*) > calculate byte_count from class list_of_fuzz and def lib_interesting_256() 
            # vs Registers Value=(Quantity of Registers OR num_values=N)*2B,
            # calculate CSV from NIST-ACTS  or all pair tools
            # list_of_fuzz().lib_interesting_256() /60 value
            elif case_FC16==False:
                parameters = [ ( "quantity"
                               , fuzz_session.quantity_of_x_list_reg_cart)
                             , ( "byte_count"
                               ,list_of_fuzz().lib_interesting_256() )
                             , ( "num_values"
                               ,fuzz_session.illegal_pdu_len)                                
                             ]
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    pairwice_Quant_vs_byte_count=self.FC16_pairwice_Quant_byte_count(parameters)
                    lgr.info('--------- case 2 combinatorial-Quantity of Registers (0x0001 to 0x007B) vs byte_count (2 x N*)--------- ')

                lgr.info('------- case 2 combinatorial (Quantity of Registers, byte_count, num of value)')
    
                fuzz_session.quantity_of_x=pairwice_Quant_vs_byte_count[0][0]
                
                lgr.info('address valid: %d ..0x%02X...' % (starting_address,starting_address))
                
                if fuzz_session.quantity_of_x >123 or fuzz_session.quantity_of_x==0:
                    lgr.warn('Write quantity invalid: %d ..0x%02X..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Write quantity valid: %d ..0x%02X..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))

                byte_count=pairwice_Quant_vs_byte_count[0][1]
                
                if byte_count >2*123 or byte_count==0:
                    lgr.warn('Byte_count invalid: %d , 0x%02X...' % (byte_count,byte_count))
                else :
                    lgr.info('Byte_count valid: %d , 0x%02X...' % (byte_count,byte_count))
                #data according to byte_count e.g value=2 byte 
                output_value=pairwice_Quant_vs_byte_count[0][2]*[self.output_value]

                lgr.info('num_values of value: %d' % (pairwice_Quant_vs_byte_count[0][2]))
                lgr.info('Byte of data value: %d' % (2*(len(output_value))))                
                
                pdu = struct.pack(">BHHB", function_code, starting_address, fuzz_session.quantity_of_x, byte_count)
                #def execute from modbus.py
                for j in output_value :
                    pdu +=struct.pack(">H",j)                
                
                fuzz_session.starting_address=starting_address
                fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
                pairwice_Quant_vs_byte_count=np.delete(pairwice_Quant_vs_byte_count, 0, 0)
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    tcc.test_case (function_code,'Quant_vs_byte_count_vs_value',['address','quantity','byte_count','len(output_value)'],np.array(fuzz_session.tmp_test_list))
                    fuzz_session.case_FC16=True
                    self.reset()
                            
                break
            else :
                pass
        return pdu
    
    def fuzz_field_parameter_FC22(self,function_code,pdu):
        """ 
        22 (0x16) Mask Write Register
        param :address=0x0000, and_mask=0xffff, or_mask=0x0000
        This function code is used to modify the contents of a specified holding register 
        The normal response is an echo of the request. 
        testing one-way field as list fuzz_session.attack_byte_PDU
        global -fuzz_session.test_wr_mask_param=['address', 'or_mask', 'and_mask'] 
           
        """
        fuzz_session.flag_boundaries=0
        tcc=test_case_coverage()                                
        starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_wr_mask_param[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field  % r ' % test_field)
           
        if test_field=='address' :                                     
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))   #shift a list
            
        elif test_field=='or_mask' :
            or_mask= fuzz_session.values_test[0]            
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))                #shift a list
        
        elif test_field=='and_mask' :
            and_mask= fuzz_session.values_test[0]           
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))
           
        else :            
            lgr.info('error Choice')
            self.reset()

        #check address    
        if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('address invalid: %d ...0x%02X .' % (starting_address,starting_address))
            fuzz_session.field1_valid  += 1
            fuzz_session.flag_boundaries=1              
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
            
        lgr.info('or_mask : %d ..0x%02X ..' % (or_mask,or_mask))
        fuzz_session.field2_valid += 1
        lgr.info('and_mask : %d ..0x%02X ..' % (and_mask,and_mask))
        fuzz_session.field3_valid += 1

        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,and_mask,or_mask])
       
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_value_last item of list
        if  starting_address==fuzz_session.l_fuzz_addre_HO_REG or or_mask==fuzz_session.l_output_value or and_mask==fuzz_session.l_output_value  :
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_wr_mask_param,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='or_mask':
                tcc.Coverage (function_code,test_field,fuzz_session.test_wr_mask_param,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='and_mask':
                tcc.Coverage (function_code,test_field,fuzz_session.test_wr_mask_param,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
                                    
            tcc.test_case (function_code,test_field,fuzz_session.test_wr_mask_param,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[];fuzz_session.fields_of_list.pop(0)    
                               
            if  len(fuzz_session.fields_of_list)==0 :
                self.reset()
                
        fuzz_session.starting_address=starting_address
        fuzz_session.and_mask=and_mask
        fuzz_session.and_mask=or_mask
        return  struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask)


    def fuzz_field_parameter_FC23(self,function_code,pdu,case_FC23=None,output_value=None):    
        """ 
        23 /( 0x17) Read_Write_Multiple_Registers - 1-way test
        field Read address, Read REGISTERS Quantity to Read 0x0001 to 0x007D
        field Write address  vs Write REGISTERS quantity (0x0001 - 0x0079)
        Quantity of Registers (0x0001 to 0x007B) 
        byte_count (2 x N*) N = Quantity of Registers,
        fuzz_session.test_FC_23=['1-way_read_starting_address', '1-way_quantity_to_Read','1-way_write_starting_address',/
        '1-way_quantity_to_Write','1-way_write_byte_count','2-way'] 
        fuzz_session.flag_boundaries=0 reset       
        """
         
        read_starting_address, quantity_to_Read, write_starting_address, quantity_to_Write,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
        message_data=pdu[10:]
        tcc=test_case_coverage()
        fuzz_session.flag_boundaries=0
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_FC_23[:]
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field % r ' % test_field)
                                                     
        if test_field=='1-way_read_starting_address' :                                         
            read_starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))                 #shift a list
        
        elif test_field=='1-way_quantity_to_Read' :
            quantity_to_Read= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))       
        
        elif test_field=='1-way_write_starting_address' :
            write_starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))

        elif test_field=='1-way_quantity_to_Write' :
            quantity_to_Write= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))      

        elif test_field=='1-way_write_byte_count' : 
            write_byte_count= fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))  
        
        elif test_field=='2-way':  
            return self.fuzz_field_two_way_parameter_FC23(function_code,pdu,case_FC23,output_value)
            
        else :
            
            lgr.info('error')
            raise    #fix to def
        
        #check fields Read
        if (read_starting_address <fuzz_session.MIN_HO_REG) or (read_starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('Read address  invalid: %d ..0x%02X ..' % (read_starting_address,read_starting_address))
            fuzz_session.field1_invalid += 1
        else :
            lgr.info('Read address  valid: %d ..0x%02X ..' % (read_starting_address,read_starting_address))
            fuzz_session.field1_valid += 1

        #Quantity to Read 0x0001 to 0x007D
        if (quantity_to_Read >125) or (quantity_to_Read==0):
            lgr.warn('Read REGISTERS quantity invalid: %d ..0x%02X ..' % (quantity_to_Read,quantity_to_Read))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Read REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_to_Read,quantity_to_Read))
            fuzz_session.field2_valid += 1

        if (read_starting_address+quantity_to_Read ) > fuzz_session.MAX_HO_REG:
            lgr.warn('(Read  address + quantity of read) is invalid : %d ..0x%02X..' % ((read_starting_address+quantity_to_Read),(read_starting_address+quantity_to_Read)))
            fuzz_session.read_address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1
        else :
            lgr.info('(Read  address + quantity of read) is  valid: %d ..0x%02X..' % ((read_starting_address+quantity_to_Read),(read_starting_address+quantity_to_Read)))
            fuzz_session.read_address_quantity_valid += 1
            
        
        # check field, Write address and  Write REGISTERS quantity     
        if (write_starting_address <fuzz_session.MIN_HO_REG) or (write_starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('Write address invalid: %d ..0x%02X ..' % (write_starting_address,write_starting_address))
            fuzz_session.field3_invalid += 1
            
        else :
            lgr.info('Write address valid: %d ..0x%02X ..' % (write_starting_address,write_starting_address))
            fuzz_session.field3_valid  += 1
            
            
        # quantity_to_Write  Quantity of Write (0x0001 - 0x0079)  
        if quantity_to_Write >121 or quantity_to_Write==0:                        
            lgr.warn('Write REGISTERS quantity invalid: %d ..0x%02X ..' % (quantity_to_Write,quantity_to_Write))
            fuzz_session.field4_invalid += 1
        else :
            lgr.info('Write REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_to_Write,quantity_to_Write))
            fuzz_session.field4_valid  += 1

        if (write_starting_address +quantity_to_Write) > fuzz_session.MAX_HO_REG :
            lgr.warn('(write address + quantity of write) is invalid : %d ..0x%02X ..' % ((write_starting_address +quantity_to_Write),(write_starting_address +quantity_to_Write)))
            fuzz_session.write_address_quantity_invalid  += 1
            fuzz_session.flag_boundaries=1
        else :  
            lgr.info('(Write address + quantity of write) is  valid: %d ..0x%02X ..' % ((write_starting_address +quantity_to_Write),(write_starting_address +quantity_to_Write)))  
            fuzz_session.write_address_quantity_valid  += 1
            
        #check Quantity of Write (0x0001 - 0x0079)
        if write_byte_count >2*123 or write_byte_count==0:
            lgr.warn('Write byte_count invalid: %d ..0x%02X ..' % (write_byte_count,write_byte_count))
            fuzz_session.field5_invalid += 1
        else :
            lgr.info('Write byte_count valid: %d ..0x%02X ..' % (write_byte_count,write_byte_count))
            fuzz_session.field5_valid  += 1
        
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([read_starting_address, quantity_to_Read, write_starting_address,quantity_to_Write,write_byte_count])
        #check -fuzz_session.l_fuzz_addre_REG,fuzz_session.l_quantity_of_REGlast item of list  ...
        if  read_starting_address==fuzz_session.l_fuzz_addre_HO_REG or quantity_to_Read==fuzz_session.l_quantity_of_REG or write_byte_count==fuzz_session.l_byte_count\
            or write_starting_address==fuzz_session.l_fuzz_addre_HO_REG or quantity_to_Write==fuzz_session.l_quantity_of_REG:
            
            if test_field=='1-way_read_starting_address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='1-way_quantity_to_Read':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='1-way_write_starting_address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='1-way_quantity_to_Write':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='1-way_write_byte_count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field5_valid, fuzz_session.field5_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            tcc.test_case (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.tmp_test_list)
            fuzz_session.tmp_test_list=[]
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))
       
        fuzz_session.read_starting_address=read_starting_address
        fuzz_session.write_starting_address=write_starting_address
        fuzz_session.quantity_to_Read=quantity_to_Read
        fuzz_session.write_byte_count=write_byte_count
        fuzz_session.quantity_to_Write=quantity_to_Write

        pdu= struct.pack(">BHHHHB",function_code,read_starting_address, quantity_to_Read, write_starting_address,quantity_to_Write,write_byte_count)
        pdu += message_data    
        return pdu

        
    def fuzz_field_two_way_parameter_FC23(self,function_code,pdu,case_FC23=None,output_value=None,dir="./tmp"):
        """ 
        Test case Initializing  Cartesian product
        23 /( 0x17) Read_Write_Multiple_Registers
        case 1: cross field Read address  vs Read REGISTERS Quantity to Read 0x0001 to 0x007D (CSV file FC16 from NIST-ACTS)
        case 2: cross field Write address  vs Write REGISTERS quantity (0x0001 - 0x0079) (CSV file FC16 from NIST-ACTS)
        case 3: Quantity of Registers (0x0001 to 0x007B) vs byte_count (2 x N*) N = Quantity of Registers,(CSV filefrom NIST-ACTS)

        """
        global  slave,pairwice_READ_HOLDING_REGISTERS,pairwice_Quant_vs_byte_count
        tcc=test_case_coverage()
        case_FC23=fuzz_session.case_FC23
        read_starting_address, quantity_to_Read, write_starting_address, quantity_to_Write,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
        message_data=pdu[10:]
             
        while True:
            # case 1: cross field Read address vs Read REGISTERS quantity 
            if case_FC23==True:
                lgr.warn('------- case 1: cross field Read address vs Read REGISTERS quantity ------')
               
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    #pairwice_READ_HOLDING_REGISTERS=list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart))       #crete list                    
                    lgr.info("------ Csv file Initializes ..")
                    
                    if os.path.exists(dir+"/FC03_pair.csv"):
                        # read CSV file & load in  list
                        with open(dir+"/FC03_pair.csv", 'r') as f:
                            lgr.info("------ Read csv file .....")
                            reader = csv.reader(f)
                            pairwise_temp = list(reader)
                            #convert all elements to init
                            pairwice_READ_HOLDING_REGISTERS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                            
                    else:
                            lgr.info("------- not file CSV, use cartesian list ..")
                            pairwice_READ_HOLDING_REGISTERS=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart)))
     
                    lgr.info('------ case 2 num of test %d'%len(pairwice_READ_HOLDING_REGISTERS))
                
                starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                
                if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
                    lgr.warn('Read address  invalid: %d ..0x%02X ..' % (starting_address,starting_address))
                else :
                    lgr.info('Read address  valid: %d ..0x%02X ..' % (starting_address,starting_address))
        
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                #Quantity to Read 0x0001 to 0x007D
                if (fuzz_session.quantity_of_x >125) or (fuzz_session.quantity_of_x==0):
                    lgr.warn('Read REGISTERS quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Read REGISTERS quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))

                if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_HO_REG:
                    lgr.warn('(Read  address + quantity of read) is invalid : %d ..0x%02X ..' % ((starting_address+fuzz_session.quantity_of_x),(starting_address+fuzz_session.quantity_of_x)))
                    fuzz_session.flag_boundaries=1
                else :
                    lgr.info('(Read  address + quantity of read) is  valid: %d ..0x%02X ..' % ((starting_address+fuzz_session.quantity_of_x),(starting_address+fuzz_session.quantity_of_x)))
                #for cas1 : Read REGISTERS quantity =fuzz_session.quantity_of_x 
                fuzz_session.read_starting_address =starting_address     
               
                pdu= struct.pack(">BHHHHB",function_code,starting_address, fuzz_session.quantity_of_x, write_starting_address, quantity_to_Write,write_byte_count)
                pdu += message_data
                fuzz_session.tmp_test_list.append ([starting_address,fuzz_session.quantity_of_x,write_starting_address, quantity_to_Write,write_byte_count])
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    tcc.test_case (function_code,'address vs quantity',['address','quantity_of_x','write_starting_address','quantity_to_Write','write_byte_count'],np.array(fuzz_session.tmp_test_list))                    
                    fuzz_session.tmp_test_list=[]
                    fuzz_session.case_FC23=False

                break         
            # case 2 cross field Write address vs Write REGISTERS quantity     
            elif case_FC23==False: 
                lgr.warn('------- case 2: cross field Write address vs Write REGISTERS quantity (0x0001 - 0x0079) ------')
                
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    #pairwice_READ_HOLDING_REGISTERS=list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart))       #crete list                    
                    lgr.info("------- Csv file Initializes..")
                    
                    if os.path.exists(dir+"/FC03_pair.csv"):
                        # read CSV file & load in  list
                        try :
                            with open(dir + "/FC03_pair.csv", 'r') as f:                           
                                lgr.info("------- Read csv file .. ..")
                                reader = csv.reader(f)
                                pairwise_temp = list(reader)
                                #convert all elements to init
                                pairwice_READ_HOLDING_REGISTERS = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                        
                        except IOError : 
                               lgr.info("------- not file NIST-ACTS, use cartesian list ..")
                               pairwice_READ_HOLDING_REGISTERS=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart)))
                                       
                    else:
                            lgr.info("------- not file NIST-ACTS, use cartesian list ..")
                            pairwice_READ_HOLDING_REGISTERS=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart)))
                    
                    lgr.info('------- case 2 num of test %d'%len(pairwice_READ_HOLDING_REGISTERS))
                
                starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]   
        
                if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
                    
                    lgr.warn('Write address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
                else :
                    lgr.info('Write address valid: %d ..0x%02X ..' % (starting_address,starting_address))
                    
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                # quantity_to_Write  Quantity of Write (0x0001 - 0x0079)  
                if fuzz_session.quantity_of_x >121 or fuzz_session.quantity_of_x==0:                        
                    lgr.warn('Write REGISTERS quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Write REGISTERS quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_HO_REG :
                    fuzz_session.flag_boundaries=1
                    lgr.warn('(write address + quantity of write) is invalid : %d ..0x%02X ..' % ((starting_address+fuzz_session.quantity_of_x),starting_address+fuzz_session.quantity_of_x))
                else :  
                    lgr.info('(Write address + quantity of write) is  valid: %d ..0x%02X ..' % ((starting_address+fuzz_session.quantity_of_x),starting_address+fuzz_session.quantity_of_x))  
                    
                #for cas2 : fuzz_session.quantity_of_x=Write REGISTERS quantity 
                fuzz_session.write_starting_address =starting_address
                pdu= struct.pack(">BHHHHB",function_code,read_starting_address, quantity_to_Read, starting_address, fuzz_session.quantity_of_x,write_byte_count)
                pdu += message_data

                fuzz_session.tmp_test_list.append ([starting_address,fuzz_session.quantity_of_x,write_starting_address, quantity_to_Write,write_byte_count])

                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    tcc.test_case (function_code,'W_address_vs_Write_quantity ',['address','quantity_of_x','write_starting_address','quantity_to_Write','write_byte_count'],np.array(fuzz_session.tmp_test_list))                    
                    fuzz_session.tmp_test_list=[]                   
                    fuzz_session.case_FC23=None    
                break
            else :
                 #calculate byte_count from class list_of_fuzz   integer exhaustive fuzz heuristics library
                parameters = [ 
                               ("quantity_write"
                               , fuzz_session.quantity_of_x_list_reg_cart)
                             , ( "byte_count"
                               ,list_of_fuzz().lib_interesting_256())
                             ,  ( "num_value"
                               ,fuzz_session.quantity_of_x_list_reg_cart)                               
                             ]
                lgr.info('------- case 3: NIST -ACTS Quantity of Registers read vs Quantity of Registers write vs byte_count (2 x N*) N = Quantity of Registers,------')
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    pairwice_Quant_vs_byte_count=self.FC23_pairwice_Quant_byte_count(parameters)
                    
                    lgr.info('case 3 : Quantity of Registers READ (0x0001 to 0x007D) vs Quantity of Registers WRITE  byte_count (2 x N*)--------- ')
                              
                if (fuzz_session.quantity_to_Read >125) or (fuzz_session.quantity_to_Read==0):
                    lgr.warn('Read REGISTERS quantity invalid: %d ...0x%02X..' % (fuzz_session.quantity_to_Read,fuzz_session.quantity_to_Read))
                else :
                    lgr.info('Read REGISTERS quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_to_Read,fuzz_session.quantity_to_Read))

                #Quantity of Write (0x0001 - 0x0079)
                fuzz_session.quantity_to_Write=pairwice_Quant_vs_byte_count[0][0]
                if fuzz_session.quantity_to_Write>121 or fuzz_session.quantity_to_Write==0:
                    lgr.warn('Write quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_to_Write,fuzz_session.quantity_to_Write))
                else :
                    lgr.info('Write quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_to_Write,fuzz_session.quantity_to_Write))

                write_byte_count=pairwice_Quant_vs_byte_count[0][1]
                
                if write_byte_count >2*121 or write_byte_count==0:
                    lgr.warn('Write byte_count invalid: %d ..0x%02X ..' % (write_byte_count,write_byte_count))
                else :
                    lgr.info('Write byte_count valid: %d ..0x%02X ..' % (write_byte_count,write_byte_count))
                #data according to byte_count e.g value=2 byte 
                output_value=pairwice_Quant_vs_byte_count[0][2]*[self.output_value]
                lgr.info('byte of data value: %d' % (2*(len(output_value))))                
                
                pdu= struct.pack(">BHHHHB",function_code,read_starting_address, fuzz_session.quantity_to_Read, write_starting_address,quantity_to_Write,write_byte_count)
                fuzz_session.tmp_test_list.append ([read_starting_address,fuzz_session.quantity_of_x,write_starting_address, quantity_to_Write,write_byte_count])
                pairwice_Quant_vs_byte_count=np.delete(pairwice_Quant_vs_byte_count, 0, 0)
                #def execute from modbus.py
                for j in output_value :
                    pdu +=struct.pack(">H",j)
                                                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    tcc.test_case (function_code,'Quant_vs_byte_count',['address','quantity_of_x','byte_count','write_starting_address','quantity_to_Write','write_byte_count'],np.array(fuzz_session.tmp_test_list))                    
                    self.reset()
                    fuzz_session.case_FC23=True                   
                break
        return pdu

    def fuzz_field_parameter_FC20(self,function_code,pdu):  
        """
       20 (0x14) Read File Record-test only 1 group
       test one-field, the rest valid   - 
       fuzz_session.test_field_Read_File_record=['Byte_Count','Reference_Type','File Number','Record Number','2-way']
       Each group is defined in a separate ‘sub-request’ field that contains 7 bytes:
       The reference type: 1 byte (must be specified as 6)
       The File number: 2 bytes-Indicates which file number -Extended Memory file number: 2 bytes (1 to 10, hex 0001 to 000A)
       The starting record number within the file: 2 bytes-Indicates which record in the file -(starting address)
       The length of the record to be read: 2 bytes.The length in registers of the record -(register count request)
       The available quantity of Extended Memory files depends upon the installed size
       of Extended Memory in the slave controller. Each file except the last one contains
       10,000 registers, addressed as 0000-270F hexadecimal (0000-9999 decimal).
       """
        
        global pairwice_file
        tcc=test_case_coverage()

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_Read_File_record[:]

        Byte_Count,Reference_Type,File_number,Read_record,Record_length=struct.unpack(">BBHHH", pdu[1:9])
        test_field = fuzz_session.fields_of_list[0] ; lgr.info('testing field: % r ' % test_field)                                                  
                  
        if test_field=='Byte_Count' :                                                         #1 BYTE
                                                      
            Byte_Count=fuzz_session.count_byte_test[0]
            fuzz_session.count_byte_test.append(fuzz_session.count_byte_test.pop(0))          #shift a list

        elif test_field=='Reference_Type' :                                                   #1 BYTE
            Reference_Type=fuzz_session.ref_byte_test[0]
            fuzz_session.ref_byte_test.append(fuzz_session.ref_byte_test.pop(0))                   
        
        elif test_field=='File_number' :
            File_number=fuzz_session.fuzz_files_rum[0]
            fuzz_session.fuzz_files_rum.append(fuzz_session.fuzz_files_rum.pop(0))             

        elif test_field=='Record_number' :
            Read_record=fuzz_session.fuzz_files_rec[0]
            fuzz_session.fuzz_files_rec.append(fuzz_session.fuzz_files_rec.pop(0))                  

        #record_length=max N=122X2 byte 244byte max, for valid len frame   
        elif test_field=='Record_length' :
            Record_length=fuzz_session.record_length[0]
            fuzz_session.record_length.append(fuzz_session.record_length.pop(0))                

        elif test_field=='2-way':  
            Byte_Count,Reference_Type,File_number,Read_record,Record_length=self.fuzz_field_two_way_parameter_FC20(function_code,pdu)
            
        else :
            lgr.warn('not fuzzing')            

        #check-conditions,field1=Byte_Coun, field2=File_Number, field3=Read_File_record 
        
        if Byte_Count>=245 or Byte_Count<=7:
            lgr.warn('Byte_Count quantity invalid: %d ..0x%02X ..' % (Byte_Count,Byte_Count))
            fuzz_session.field1_invalid += 1
        else :
            lgr.info('Byte_Count quantity valid: %d ..0x%02X ..' % (Byte_Count,Byte_Count))
            fuzz_session.field1_valid += 1

        if Reference_Type!=6:
            lgr.warn('Reference_Type value invalid: %d .. 0x%02X ..' % (Reference_Type,Reference_Type))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Reference_Type value  valid: %d ..0x%02X ..' % (Reference_Type,Reference_Type))
            fuzz_session.field2_valid += 1

        if File_number>10 or File_number==0:
            lgr.warn('File_Number value invalid: %d ..0x%02X ..' % (File_number,File_number))
            fuzz_session.field3_invalid += 1
        else :
            lgr.info('File_Number value valid: %d ..0x%02X ..' % (File_number,File_number))
            fuzz_session.field3_valid += 1    

        if (Read_record >9999 ):
            lgr.warn('record_number  invalid: %d ..0x%02X ..' % (Read_record,Read_record))
            fuzz_session.field4_invalid+= 1
        else :
            lgr.info('record_number valid : %d ..0x%02X ..' % (Read_record,Read_record))
            fuzz_session.field4_valid+= 1
            
        if (Read_record+Record_length) > 9999 :
            lgr.warn('(Read record + record_length read)  is invalid : %d ....' % (Read_record+Record_length))
        else :  
            lgr.info('(Read record + record_length read) is  valid: %d ....' % (Read_record+Record_length))      

        if Record_length<122:
            lgr.info('Record_length value valid: %d ..0x%02X ..' % (Record_length,Record_length))
            fuzz_session.field5_valid += 1            
        
        else :
            lgr.warn('Record_length value  invalid: %d ..0x%02X ..' % (Record_length,Record_length ))
            fuzz_session.field5_invalid += 1
                    

         # e.g l.append([1,2,3])-create a list of lists only 20 records        
        fuzz_session.tmp_test_list.append ([Byte_Count,Reference_Type,File_number,Read_record,Record_length])
       
        #check -for last item of list
        if  (test_field=='Byte_Count'and Byte_Count==fuzz_session.l_count_byte_test) or (test_field=='Reference_Type' and Reference_Type==fuzz_session.l_ref_byte_test) or \
            (test_field=='File_number' and File_number==fuzz_session.l_lib_of_files_rum) or (test_field=='Record_number'and Read_record==fuzz_session.l_lib_of_files_rec) or \
            (test_field=='Record_length' and Record_length==fuzz_session.l_record_length):
            
            if test_field=='Byte_Count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            if test_field=='Reference_Type':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            if test_field=='File_number':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=65535)     
            
            if test_field=='Record_Number':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=65535)     
            
            if test_field=='Record_length': 
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field5_valid, fuzz_session.field5_invalid,np.array(fuzz_session.tmp_test_list),t=65535)
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_Read_File_record,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))    
        
        elif (len(pairwice_file)==0 and test_field=='2-way'):
            
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field4_valid,fuzz_session.field4_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field5_valid,fuzz_session.field5_invalid])            
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.tmp_list_of_case,t=65535) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_Read_File_record,np.array(fuzz_session.tmp_test_list))
            self.reset()
            
        record1 = (File_number,Read_File_record,Record_length)
        fuzz_session.f_record1 ='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Read_record,Record_length) 
        return  struct.pack(">BBBHHH",function_code,Byte_Count,Reference_Type,File_number,Read_record,Record_length)
              

    def fuzz_field_parameter_FC21(self,function_code,pdu):
        """
        Write File Record  FC 21
        test one-field, the rest valid   - 
        fuzz_session.test_field_Write_File_record=['Data_length','Reference_Type','File number','Record number','Record_length',Record data',2-way']
        file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
        self.record_length = kwargs.get('record_length', len(self.record_data) / 2)
        max value for self.record_data  is 244 Byte, self.record_length=max N=122X2 byte
         
        """        
        global pairwice_file
        tcc=test_case_coverage()

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_Write_File_record[:]
        test_field = fuzz_session.fields_of_list[0]                                                    
        lgr.info('testing field: % r ' % test_field)
                                                                       
        Data_length,Reference_Type,File_number,Write_record,Record_length= struct.unpack(">BBHHH", pdu[1:9])
        Record_data=pdu[9:]
    
        if test_field=='Data length' :#Request_Data_length                  
            Data_length=fuzz_session.count_byte_test[0]
            fuzz_session.count_byte_test.append(fuzz_session.count_byte_test.pop(0))           #shift a list

        elif test_field=='Reference Type' :
            Reference_Type=fuzz_session.ref_byte_test[0]
            fuzz_session.ref_byte_test.append(fuzz_session.ref_byte_test.pop(0))               #shift a list    
        
        elif test_field=='File number' :
            File_number=fuzz_session.fuzz_files_rum[0]
            fuzz_session.fuzz_files_rum.append(fuzz_session.fuzz_files_rum.pop(0))             #shift a list 

        elif test_field=='Record number' :
            Write_record=fuzz_session.fuzz_files_rec[0]
            fuzz_session.fuzz_files_rec.append(fuzz_session.fuzz_files_rec.pop(0))             #shift a list     

        #record_length=max N=122X2 byte for len 260 packet   
        elif test_field=='Record length' :
            Record_length=fuzz_session.record_length[0]
            fuzz_session.record_length.append(fuzz_session.record_length.pop(0))                #shift a list

        elif test_field=='Record data' :                
            #Read_File_record=fuzz_session.fuzz_files_rec[0]                         
            Record_data =self.test_field_of_data(fuzz_session.fuzz_files_rec[0])
            fuzz_session.fuzz_files_rec.append(fuzz_session.fuzz_files_rec.pop(0))
        
        elif test_field=='2-way':              
            #only test group 0 and fuzz test Record_data 
            Data_length,Reference_Type,File_number,Write_record,Record_length,output_value=self.fuzz_field_two_way_parameter_FC21(function_code,pdu)            
            #output_value=output_value*[self.output_value]
            for j in output_value*[self.output_value] : Record_data +=struct.pack(">H",j)
                
                        
        else :
            lgr.info('not fuzzing')    

         #check-conditions,field1=Byte_Coun, field2=File_Number, field3=Read_File_record ....
        if Data_length>=251 or Data_length<=9:
            lgr.warn('Data length quantity invalid: %d ..0x%02X..' % (Data_length,Data_length))
            fuzz_session.field1_invalid += 1
        else :
            lgr.info('Data length quantity valid: %d ..0x%02X..' % (Data_length,Data_length))
            fuzz_session.field1_valid += 1

        if Reference_Type!=6:
            lgr.warn('Reference Type value invalid: %d ..0x%02X..' % (Reference_Type,Reference_Type))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Reference_Type value  valid: %d ..0x%02X..' % (Reference_Type,Reference_Type))
            fuzz_session.field2_valid += 1

        if File_number>10 or File_number==0:
            lgr.warn('File number value invalid: %d ..0x%02X..' % (File_number,File_number))
            fuzz_session.field3_invalid += 1
        else :
            lgr.info('File number valid: %d ..0x%02X..' % (File_number,File_number))
            fuzz_session.field3_valid += 1    

        if (Write_File_record >9999):
            lgr.warn('record_number invalid: %d ..0x%02X..' % (Write_record,Write_record))
            fuzz_session.field4_invalid+= 1
        else :
            lgr.info('record_number valid : %d ..0x%02X..' % (Write_record,Write_record))
            fuzz_session.field4_valid+= 1
            
        if (Write_File_record+Record_length) > 9999 :
            lgr.warn('(Write record_number + record_length read)  is invalid : %d ....' % (Write_record+Record_length))
        else :  
            lgr.info('(Write record_number + record_length read) is  valid: %d ....' % (Write_record+Record_length))      

        if Record_length==(len(Record_data)/2):
            lgr.info('Record_length value valid: %d ..0x%02X..' % (Record_length,Record_length))
            fuzz_session.field5_valid += 1  
        else :
            lgr.warn('Record_length value  invalid: %d ..0x%02X..' % (Record_length,Record_length))
            fuzz_session.field5_invalid += 1

        if (len(Record_data))<=244:                  #record_length=max N=122X2 byte for len 260 packet
            lgr.info('Record data len value  valid: %d ..0x%02X..' % (len(Record_data),len(Record_data)))
            fuzz_session.field6_valid += 1  
        else :
            lgr.warn('Record data len value  invalid: %d ..0x%02X..' % (len(Record_data),len(Record_data)))
            fuzz_session.field6_invalid += 1    
        
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([Data_length,Reference_Type,File_number,Write_record,Record_length,len(Record_data)])
        #check -for last item of list
        if  (test_field=='Data length'and Data_length==fuzz_session.l_count_byte_test) or (test_field=='Reference Type' and Reference_Type==fuzz_session.l_ref_byte_test) or \
            (test_field=='File number' and File_number==fuzz_session.l_lib_of_files_rum) or (test_field=='Record number'and Write_record==fuzz_session.l_lib_of_files_rec) or \
            (test_field=='Record length' and Record_length==fuzz_session.l_record_length)or \
            (test_field=='Record data' and (len(Record_data)==fuzz_session.l_fuzz_files_rec)) :
            
            if test_field=='Data length':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            if test_field=='Reference Type':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            if test_field=='File number':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=65535)     
            
            if test_field=='Record number':                  
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=65535)     
            
            if test_field=='Record length':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field5_valid, fuzz_session.field5_invalid,np.array(fuzz_session.tmp_test_list),t=65535)
            
            if test_field=='Record data':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field6_valid, fuzz_session.field6_invalid,np.array(fuzz_session.tmp_test_list),t=65535)

            tcc.test_case (function_code,test_field,fuzz_session.test_field_Write_File_record,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]

            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))
        
        
        elif (len(pairwice_file)==0 and test_field=='2-way'):
            
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field4_valid,fuzz_session.field4_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field5_valid,fuzz_session.field5_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field6_valid,fuzz_session.field6_invalid])            
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.tmp_list_of_case,t=65535) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_Write_File_record,np.array(fuzz_session.tmp_test_list))
            self.reset()
            
        record1 = (File_number,Write_File_record,Record_length)
        fuzz_session.f_record1 ='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Write_record,Record_length) # only first group fuz test
        pdu  = struct.pack(">BBBHHH",function_code,Data_length,Reference_Type,File_number,Write_record,Record_length)                  
        pdu += Record_data       
        return pdu  
            
    def fuzz_field_two_way_parameter_FC20(self,function_code,pdu,dir='Nist-csv'):
        
        """20 (0x14) Read File Record
        file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
        record_length   = kwargs.get('record_length', len(self.record_data) / 2)
        record_num =(0,9999)

        # ACTS Test Suite Generation: Wed Mar 18 20:43:59 EET 2020/ -CSV FILE
  '     *' represents don't care value 
        Degree of interaction coverage: 2
        Number of parameters: 5
        Maximum number of values per parameter: 75
        Number of configurations: 5667
        Byte_count,Reference_Type,File_numbe    
           
        """
        global pairwice_file
        
        if  len(pairwice_file)==0 :
                #pairwice_READ_HOLDING_REGISTERS=list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart))       #crete list                    
                lgr.info("------- NIST-ACTS-csv  file Initializes..")
                
                if os.path.exists(dir+"/FC20_pair.csv"):
                    # read CSV file & load in  list
                    try :
                        with open(dir + "/FC20_pair.csv", 'r') as f:                           
                            lgr.info("------- Read csv file .. ..")
                            reader = csv.reader(f)
                            pairwise_temp = list(reader)
                            #convert all elements to init
                            pairwice_file = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                    
                    except IOError : 
                           lgr.info("------- not file NIST-ACTS, not test 2-way ..")
                           self.reset()                                   
                else:
                        
                        lgr.info("------- not file NIST-ACTS, not test 2-way ..")
                        self.reset()                                      
                lgr.info('------- num of test %d'%len(pairwice_file))
        #Check group) / 4 parameter 
        Byte_Count=pairwice_file[0][0];Reference_Type=pairwice_file[0][1]
        File_number=pairwice_file[0][2];Read_File_record=pairwice_file[0][3]     
        Record_length =pairwice_file[0][4]     
        pairwice_file=np.delete(pairwice_file, 0, 0)
     
        return  Byte_Count,Reference_Type,File_number,Read_File_record,Record_length  


    def fuzz_field_two_way_parameter_FC21(self,function_code,pdu,dir='./Nist-csv'):
        """
        Write File Record  FC 21
        file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
        self.record_length   = kwargs.get('record_length', len(self.record_data) / 2)
        record_num =(0,9999)

         ACTS Test Suite Generation: Wed Mar 18 20:47:30 EET 2020
          '*' represents don't care value 
         Degree of interaction coverage: 2
         Number of parameters: 6
          Maximum number of values per parameter: 183
         Number of configurations: 7363

        """
        global pairwice_file   
        if  len(pairwice_file)==0 :
                lgr.info("------- NIST-ACTS-csv  file Initializes..")
                
                if os.path.exists(dir+"/FC21_pair.csv"):
                    # read CSV file & load in  list
                    try :
                        with open(dir + "/FC21_pair.csv", 'r') as f:                           
                            lgr.info("------- Read csv file .. ..")
                            reader = csv.reader(f)
                            pairwise_temp = list(reader)
                            #convert all elements to init
                            pairwice_file = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                    
                    except IOError : 
                           lgr.info("------- not file NIST-ACTS, not test 2-way ..")
                           self.reset()                                   
                else:
                        
                        lgr.info("------- not file NIST-ACTS, not test 2-way ..")
                        self.reset()                                      
                lgr.info('------- num of test %d'%len(pairwice_file))
        #and output_value for record data
        Data_length=pairwice_file[0][0];Reference_Type=pairwice_file[0][1]       
        File_number=pairwice_file[0][2];Write_File_record=pairwice_file[0][3]        
        Record_length =pairwice_file[0][4];output_value=pairwice_file[0][5]     
        pairwice_file=np.delete(pairwice_file, 0, 0)       
        #return   Reference_Type,File_number,Write_File_record,Record_length #grup 0
        return   Data_length,Reference_Type,File_number,Write_File_record,Record_length,output_value 
    

    def fuzz_field_parameter_FC43(self,function_code,pdu):
        """  
        testing one-way
        Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
        function_code = 0x2b, sub_function_code = 0x0e
        Read Device ID code                      Object Name
        DeviceInformation_Basic:  0x01,         range [0x00 -0x02]    
        DeviceInformation_Regular= 0x02 ,       range [0x03 -0x7F]
        DeviceInformation_Extended= 0x03 ,      range [0x80–0xFF] 
        DeviceInformation_Specific= 0x04 , 
       
        fuzz_session.test_FC43=['1-way_mei_type','1-way_read_code','1-way_object_id','2-way' ]
        """ 
        global pairwice_file,pairwice_Read_device_Ident
        fuzz_session.flag_boundaries=0
        tcc=test_case_coverage()             
        mei_type,read_code,object_id = struct.unpack(">BBB", pdu[1:5])        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.  test_FC43[:]
        test_field = fuzz_session.fields_of_list[0]                                 
        lgr.info('testing field: % r ' % test_field)
                                           
        if test_field=='1-way_mei_type' :                                                     
            mei_type=fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))           #shift a list

        elif test_field=='1-way_read_code' :
            read_code=fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))           #shift a list
            
        elif test_field=='1-way_object_id' :
            object_id =fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))       
            
            
        elif test_field=='2-way':  
            mei_type,read_code,object_id=self.fuzz_field_two_way_FC43(function_code,pdu)

        else :
            self.reset()
            lgr.info('error')    

        #Check  mei_type, read_code, object_id specification valid   
        if mei_type !=14:
           
           lgr.warn('mei_type invalid: %d ..0x%02X ..' % (mei_type,mei_type))
           fuzz_session.field1_invalid += 1
           fuzz_session.flag_boundaries=1
        
        else :
            lgr.info('mei_type valid:  %d ..0x%02X ..' % (mei_type, mei_type))
            fuzz_session.field1_valid+= 1

        if read_code>4 or read_code==0:
            
            lgr.warn('read_code invalid: % d ..0x%02X ..' % (read_code,read_code))
            fuzz_session.field2_invalid += 1
            fuzz_session.flag_boundaries=1
        
        else :
            lgr.info('read_code valid: %d ..0x%02X ..' % (read_code,read_code))
            fuzz_session.field2_valid += 1

        #check, read_code combinate object_id invalid
        if read_code==1 and object_id >2 :
            lgr.warn('DeviceInformation_Basic: 0x01, Object id [0x00 -0x02] ') 
            lgr.warn('object_id invalid: %d .. 0x%02X ..' % (object_id,object_id))
            fuzz_session.field3_invalid += 1
            fuzz_session.flag_boundaries=1
        
        elif read_code==2 and  (object_id <3 or object_id>127):
            lgr.warn('DeviceInformation_Regular= 0x02, Object id [0x03 -0x7F] ')
            lgr.warn('object_id invalid: %d .. 0x%02X ..' % (object_id,object_id))
            fuzz_session.field3_invalid  += 1
            fuzz_session.flag_boundaries=1
        
        elif read_code==3 and object_id<128:
            lgr.warn('DeviceInformation_Extended= 0x03, Object id  [0x80–0xFF]')
            lgr.warn('object_id invalid: %d .. 0x%02X ..' % (object_id,object_id))
            fuzz_session.field3_invalid += 1 
            fuzz_session.flag_boundaries=1   
        
        else: 
            lgr.info('valid object_id: %d ..0x%02X ' % (object_id,object_id))
            fuzz_session.field3_valid  += 1

        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([mei_type,read_code,object_id])
       
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_value_last item of list
        if  (mei_type==fuzz_session.l_byte_count and test_field=='1-way_mei_type') or (read_code==fuzz_session.l_byte_count and test_field=='1-way_read_code' ) \
            or (object_id==fuzz_session.l_byte_count and test_field=='1-way_object_id')  :
            
            if test_field=='1-way_mei_type':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC43,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=256) 

            if test_field=='1-way_read_code':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC43,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=256) 
            
            if test_field=='1-way_object_id':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC43,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=256) 
           
            tcc.test_case (function_code,test_field,fuzz_session.test_FC43,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            #l.insert(newindex, l.pop(oldindex))
            
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))
        
        elif (len(pairwice_Read_device_Ident)==0 and test_field=='2-way'):
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_FC43,fuzz_session.tmp_list_of_case,t=65535) 
            tcc.test_case (function_code,test_field,fuzz_session.test_FC43,np.array(fuzz_session.tmp_test_list))
            self.reset()
           
        fuzz_session.mei_type=mei_type
        fuzz_session.read_code=read_code
        fuzz_session.object_id=object_id
        
        return  struct.pack(">BBBB", function_code,mei_type,read_code,object_id)
   
    def fuzz_field_two_way_FC43(self,function_code,pdu):
        """  
        Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
        function_code = 0x2b, sub_function_code = 0x0e --dec14
        cross  pairs field of MEI Type",Read Dev Id code"and Object_Id
        0x00 <= self.object_id <= 0xff) and  (0x00 <= self.read_code <= 0x04), 
        Extended: , range(0x80, i)

        """
        parameters= [ ( "MEI Type"
                       , [14])
                     , ( "Read Dev Id code"
                       ,  list_of_fuzz().lib_interesting_256())
                     , ( "Object_Id"
                       , list_of_fuzz().lib_interesting_256())
                     ]

        global  slave,lib_word_binary,pairwice_WRITE_SINGLE_REGISTER,pairwice_Read_device_Ident,pairwice_WRITE_SINGLE_COIL,pairwice_READ_COILS,pairwice_READ_INPUT_REGISTERS,pairwice_READ_HOLDING_REGISTERS,pairwice_READ_DISCRETE_INPUTS
        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        if  len(pairwice_Read_device_Ident)==0 :
                pairwice_Read_device_Ident= self.FC43_pairwise(parameters,function_code)

        mei_type=pairwice_Read_device_Ident[0][0]        
        read_code=pairwice_Read_device_Ident[0][1]                
        object_id=pairwice_Read_device_Ident[0][2]
        pairwice_Read_device_Ident=np.delete(pairwice_Read_device_Ident, 0, 0)
           
        return   mei_type,read_code,object_id
    
    
    def fuzz_field_parameter_FC24(self,function_code,pdu):
        
        """ Read Fifo Queue  FC : 24, 
        the query specifies the starting 4XXXX reference to be read from the FIFO queue
        Test that response for read ReadFifoQueueRequestEncode function,
        NOT write results to file *.csv for test single field,NOT write results  Coverage  
        """
        Pointer_address, = struct.unpack(">H", pdu[1:3])                                                  
        lgr.info('testing field: Pointer_address')                              
        fuzz_session.Pointer_address=fuzz_session.fuzz_addre_HO_REG[0]
        lgr.info('Pointer_address: %d ..0x%02X ..' % (fuzz_session.Pointer_address,fuzz_session.Pointer_address))
        fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))                     #shift a list
        if fuzz_session.Pointer_address==fuzz_session.l_fuzz_addre_HO_REG:            
            fuzz_session.flag_reguest=False              #Stop reguest /and fuzzer        
        
        return struct.pack(">BH", function_code,fuzz_session.Pointer_address)                        

    def fuzz_field_parameter_FC08(self,function_code,pdu):
    
        '''08 (0x08) Diagnostics (Serial Line only)
        1-way sub-function code test ,data field "\x00\x00" or randomize
        global -fuzz_session.Diagnostics_FC_param=['1-way_sub-function','1-way_data','2-way' ]
        function uses a two–byte sub-function code field in the query. The server echoes both the function code and sub-function code in a normal
        response. Some of the diagnostics cause data to be returned from the remote device in the
        data field of a normal response.
        Sub-function  2 Bytes , Data Field (Request) Sub-function 2 Bytes, Data Field (Response) 00 00 Any Echo Request Data
        '''               
        tcc=test_case_coverage()        
        supportedsubDiagnostics = []       
        subfunction,data= struct.unpack(">HH", pdu[1:])

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.Diagnostics_FC_param[:]
        test_field = fuzz_session.fields_of_list[0]; lgr.info('testing field: % r ' % test_field)                                
                               
        if test_field=='1-way_sub-function' :                                                                                                     
            subfunction=fuzz_session.lib_test_sub_diag[0]
            fuzz_session.lib_test_sub_diag.append(fuzz_session.lib_test_sub_diag.pop(0))           #shift a list
            
        elif test_field=='1-way_data' :
            data=fuzz_session.values_test[0]
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))                        
                
        #test case from class TestQueriesSerialFC and def test_DiagnosticRequests_data_field    
        elif test_field=='2-way':  
            lgr.info('test_DiagnosticRequests_data_field..')
            if fuzz_session.flag_test_FC08_pair==True:pass
            else:
	            fuzz_session.flag_reguest=False               #Stop reguest /and fuzzer
	            fuzz_session.test_flag_parameter_PDU=True     #test parameter_PDU
	            fuzz_session.test_flag_fc=False               #disable/enable test FC for next FC
              
        else :
            lgr.info('\n \t \t \t ...error testing diagnostics subcodes..and data fail') 
        
        #check-subfunction  
        if subfunction >21 or subfunction==19 or 5 <= subfunction <= 9 :
            #lgr.warn('')
            lgr.warn('subfunction invalid:  ..%d..0x%02X' % (subfunction,subfunction))
            fuzz_session.field1_invalid += 1
        
        elif  subfunction==4 :
            lgr.warn('subfunction  ForceListenOnlyModeRequest:  ..%d..0x%02X' % (subfunction,subfunction))
            fuzz_session.field1_valid += 1

        else :
            lgr.info('subfunction valid:  ..%d.0x%02X' % (subfunction,subfunction))
            fuzz_session.field1_valid  += 1  
        
        lgr.info('data: ..%d... 0x%04X ....' %(data,data))
        fuzz_session.field2_valid  += 1
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([subfunction,data])
      
        #check -if and  test '1-way_data', fuzz_session.flag_reguest=False, stop reguest from  tsf.test_DiagnosticRequests() 
        # in class TestQueriesSerialFC ,fuzz_session.l_output_value=fuzz_session.values_test[-1]
        if  (subfunction== fuzz_session.l_item_test_sub_diag and test_field=='1-way_sub-function') \
        or (data==fuzz_session.l_output_value and test_field=='1-way_data' ) :
                        
            if test_field=='1-way_sub-function':
                tcc.Coverage (function_code,test_field, fuzz_session.Diagnostics_FC_param,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='1-way_data':
                tcc.Coverage (function_code,test_field, fuzz_session.Diagnostics_FC_param,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
                fuzz_session.flag_reguest=False                
                         
            tcc.test_case (function_code,test_field,fuzz_session.Diagnostics_FC_param,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            #l.insert(newindex, l.pop(oldindex))          
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))
   
        return  struct.pack(">BHH", function_code,subfunction,data) 

    def fuzz_field_FC(self,function_code,pdu):

        """The functions below Testing field FC
           FC List Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.
           User-defined codes in the ranges {65-72, 100-110}, Modbus exception codes {128-255}
        """ 
        if  fuzz_session.flag_public_codes==True:
            # Making a flat list out of list of lists
            if  len(fuzz_session.public_codes)==0 :
                #fuzz_session.public_codes=reduce(operator.concat, [x for t in self.public_codes for x in t])
                fuzz_session.public_codes=self.public_codes 
                try :
                    fuzz_session.public_codes.remove(function_code)
                except:
                    pass    
                
            function_code = fuzz_session.public_codes[0]           
            lgr.warn('case 1: test public_codes {1-64, 73-99, 111-127}. ------')                                                           
            lgr.warn('test public_codes  : %d ..0x%02X ..' % (function_code,function_code))
                      
            fuzz_session.public_codes.pop(0)
            
            if len(fuzz_session.public_codes)==0 :
                fuzz_session.flag_public_codes=False
                #lgr.info('--------------------------    test User-defined functions code  -------------------------------------------\n')
                
        elif  fuzz_session.flag_user_codes==True:
            if len(fuzz_session.user_codes)==0 :
                fuzz_session.user_codes=self.User_defined_codes
            
            function_code = fuzz_session.user_codes[0]                                                        
            lgr.warn('test User-defined function_code  : %d ..0x%02X ..' % (function_code,function_code ))

            fuzz_session.user_codes.pop(0)
            if len(fuzz_session.user_codes)==0 :
                fuzz_session.flag_user_codes=False
              
        elif  fuzz_session.flag_exeption_codes==True :         
            if len(fuzz_session.exeption_codes)==0 :
                fuzz_session.exeption_codes=self.exeption_codes
            function_code = fuzz_session.exeption_codes[0]
            
            lgr.warn('case 3: exeption_codes function_code {128-255} ------')                                                           
            lgr.warn('test exeption_codes function_code : %d ..0x%02X ..' % (function_code,function_code)) 

            fuzz_session.exeption_codes.pop(0)
            if len(fuzz_session.exeption_codes)==0 :
                
                fuzz_session.flag_user_codes=False               #not run for another FC
                fuzz_session.flag_public_codes=True
                fuzz_session.test_flag_fc=False
                fuzz_session.test_flag_parameter_PDU=True        #next test for FC                   
               
        return  struct.pack(">B", function_code)+pdu[1:]   
        

    # --------------------------------------------------------------------------------------#
    #This functions fuzzes a field of pdu  (** look specification Modbus)
    #testing gramar for FC  01,02,03,04,5,6,15,16,23,21 22,43
    #---------------------------------------------------------------------------------------#  
    
    def fuzz_field_pdu(self,pdu):
        global  slave,lib_word_binary,pairwice_WRITE_SINGLE_REGISTER,pairwice_Read_device_Ident,pairwice_WRITE_SINGLE_COIL,pairwice_READ_COILS,pairwice_READ_INPUT_REGISTERS,pairwice_READ_HOLDING_REGISTERS,pairwice_READ_DISCRETE_INPUTS
        all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2
        function_code, = struct.unpack(">B", pdu[0])
        lgr.info('The function_code is % s'  % function_code)  
        adu="" 
        
        if  function_code == Read_Exception_Status or function_code == Get_Comm_Event_Counter or function_code == Get_Comm_Event_Logs or function_code == Report_Slave_Id :
        	fuzz_session.test_flag_fc=False
        #else :fuzz_session.test_flag_fc=True
        while True:

            # case 1/test illegal fc
            if fuzz_session.test_flag_fc==True:
                pdu=self.fuzz_field_FC(function_code,pdu)
                break

            # case 2/1-way and 2-way test parameter PDU
            if fuzz_session.test_flag_parameter_PDU==True:
                lgr.info('test parameter PDU ')
                if function_code == READ_COILS :
                    lgr.info('FC 01: READ_COILS ')
                    pdu=self.fuzz_field_parameter_FC01(function_code,pdu)
                    break
                elif function_code == READ_DISCRETE_INPUTS :    
                    lgr.info('FC 02: READ_DISCRETE_INPUTS')
                    pdu=self.fuzz_field_parameter_FC02(function_code,pdu)
                    break
                elif function_code == READ_HOLDING_REGISTERS :    
                    lgr.info('FC 03: READ_HOLDING_REGISTERS')
                    pdu=self.fuzz_field_parameter_FC03(function_code,pdu)
                    break

                elif function_code == READ_INPUT_REGISTERS :    
                    lgr.info('FC 04: READ_INPUT_REGISTERS')
                    pdu=self.fuzz_field_parameter_FC04(function_code,pdu)
                    break    

                elif function_code == WRITE_SINGLE_COIL :    
                    lgr.info('FC 05: WRITE SINGLE COIL')
                    pdu=self.fuzz_field_parameter_FC05(function_code,pdu)
                    break    
                
                elif function_code == WRITE_SINGLE_REGISTER :    
                    lgr.info('FC 06: WRITE_SINGLE_REGISTER')
                    pdu=self.fuzz_field_parameter_FC06(function_code,pdu)
                    break 

                elif function_code == WRITE_MULTIPLE_COILS :    
                    lgr.info('FC 15: WRITE_MULTIPLE_COILS')
                    pdu=self.fuzz_field_parameter_FC15(function_code,pdu)
                    break     

                elif function_code == WRITE_MULTIPLE_REGISTERS :    
                    lgr.info('FC 16: WRITE_MULTIPLE_REGISTERS')
                    pdu=self.fuzz_field_parameter_FC16(function_code,pdu)
                    break     
                
                elif function_code == Mask_Write_Register :    
                    lgr.info('FC 22: Mask Write Register')
                    pdu=self.fuzz_field_parameter_FC22(function_code,pdu)
                    break 

                elif function_code == Read_Write_Multiple_Registers :    
                    lgr.info('FC 23: Read_Write_Multiple_Registers')
                    pdu=self.fuzz_field_parameter_FC23(function_code,pdu)
                    break 

                elif function_code == Read_File_record :    
                    lgr.info('FC 20: Read_File_record')
                    pdu=self.fuzz_field_parameter_FC20(function_code,pdu)
                    break

                elif function_code == Write_File_record  :    
                    lgr.info('FC 21: Write_File_record ')
                    pdu=self.fuzz_field_parameter_FC21(function_code,pdu)
                    break

                elif function_code == Read_FIFO_queue  :    
                    lgr.info('FC 24 : Read_FIFO_queue')
                    pdu=self.fuzz_field_parameter_FC24(function_code,pdu)
                    break 
                
                elif function_code == Read_device_Identification  :    
                    lgr.info('FC 43 : Read_device_Identification')
                    pdu=self.fuzz_field_parameter_FC43(function_code,pdu)
                    break
                
                #-----------------------------------------------------------------------------#
                #Serial  FC  except Diagnostics
                #defaults test case from class TestQueriesSerialFC  and test_DiagnosticRequests()
                #if flag_test_FC08_pair=True then test 2-way and
                #test case from class TestQueriesSerialFC and def
                #test_DiagnosticRequests_data_field
                #------------------------------------------------------------------------------#     
                elif function_code == Diagnostics :    
                    lgr.info('FC 8 : Diagnostics ')
                    fuzz_session.flag_test_FC08_pair=True                    
                    pdu=self.fuzz_field_parameter_FC08(function_code,pdu)
                    break 

                elif function_code == Read_Exception_Status :    
                    lgr.info('FC 7 : Read_Exception_Status/not parameters PDU ')
                    fuzz_session.flag_reguest=False                    
                    break

                elif function_code == Get_Comm_Event_Counter :    
                    lgr.info('FC 11 : Get_Comm_Event_Counter/not parameters PDU ')
                    fuzz_session.flag_reguest=False
                    break             
                
                elif function_code == Get_Comm_Event_Logs  :    
                    lgr.info('FC 12 : Get_Comm_Event_Logs / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break   
                
                elif function_code == Report_Slave_Id  :    
                    lgr.info('FC 17 : Report_Slave_Id / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break    
                
                else:
                    fuzz_session.FCmergedlist.insert(len(fuzz_session.FCmergedlist)+1,fuzz_session.FCmergedlist.pop(0))    #list rotate
                    lgr.info('function_code: %d ....' % function_code)
                    return adu,pdu 
            #else case 3/Initializes
            lgr.info ('Initializes')
            fuzz_session.flag_reguest=True
            fuzz_session.test_flag_parameter_PDU=True
            fuzz_session.flag_public_codes=False
            fuzz_session.flag_User_defined_codes=False
            fuzz_session.flag_exeption_codes=False 
            fuzz_session.test_flag_fc=True
            break
        
        return adu,pdu     
                
#------------------------------------------------------------------------------------------------------#
#This class fuzz testing  a field of mbap Modbus protocol
#Modbus application protocol (MBAP) in addition to the Modbus application PDU used in the serial protocol
#The MBAP header has four fields: (i) transaction identifier, (ii) protocol identifier, (iii) length, 
#and (iv) unit identifier. The transaction identifier permits devices to pair matching requests
#and replies on a communication channel.
# [         MBAP Header         ]      [ Function Code] [ Data ]
# [ tid ][ pid ][ length ][ uid ]
#    2b     2b     2b        1b           1b             Nb
#-------------------------------------------------------------------------------------------------------#

class fuzz_test_MBAP():

    def __init__(self):
        
        self.len=[0,1,2,3,4,5,6]
        self.mbap=modbus_tcp_b.TcpMbap_b()

    def __len__(self):
        return 0

    lof=list_of_fuzz()      
    
    def reset(self):
        '''
        This function  return list of use coverage and flag for fuzzing PDU
        fuzz_session.rows_of_cover=[]-- return list of use class coverage 

        '''        
        fuzz_session.tmp_list_of_case=[]
        fuzz_session.fields_of_list=[]
        fuzz_session.tmp_test_list=[]
        fuzz_session.rows_of_cover=[]

        fuzz_session.flag_reguest=False              #Stop reguest /and fuzzer  
   


    def MBAP_pairwice(self,dir='./Nist-csv'):
        """ 
       PAIRWISE  test for MBAP from ./Nist-csv
       read CSV file & load in list of list, convert all elements to init
       sort length field  
       ACTS Test Suite Generation: Sat Sep 26 20:39:43 EEST 2020
        # Maximum number of values per parameter: 173
        # Number of configurations: 21815
       mbap_transaction,mbap_protocol,mbap_len,mbap_slave
        0,0,1,1
        0,1,2,2
        0,2,3,3
        0,3,4,4
        0,4,5,5
        0,5,6,6
        0,6,7,7
            ..
        """        
        
        lgr.info("PAIRWISE list Initializes")
        try:
            if os.path.exists(dir+"/MBAP_pair.csv"):            
                with open(dir+"/MBAP_pair.csv", 'r') as f:
                    lgr.info("Read MBAP CSV ..")
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    pairwise = list(map(lambda line: [int(x) for x in line],pairwise_temp))
                    pairwise.sort(key = lambda row: row[2])         #sort length field        
            else:
                    lgr.error("PAIRWISE CSV not exist..")
                    fuzz_session.flag_reguest=False                 #Stop reguest and fuzzer
                    #raise    #fix   
                     
        except IOError :
            lgr.exception('')
            fuzz_session.flag_reguest=False 
            raise

        if len(pairwise)==0:
            raise ValueError ('no data')
            fuzz_session.flag_reguest=False 

        lgr.info('--------- Test case Initializing --------- : %d '% len(pairwise))
        return pairwise        
      
    def TransIdIs(self):
        """
           the function increasing/decrasing the transaction id
           This function invalid transaction_id in the mbap
        """
        global flag_IDs       
        query = modbus_tcp_b.TcpQuery_b()
        last_transaction_id  = query.get_transaction_id_b()
        #return random.randint(100,65535)
        return 100
    
    def mbap_custom(self):       
        """ 2-way Combinatorial testing """
        
        global  slave,pairwice_MBAP       
        if  len(pairwice_MBAP)==0 :  pairwice_MBAP= self.MBAP_pairwice()                                
        self.mbap.transaction_id =pairwice_MBAP[0][0]
        self.mbap.protocol_id = pairwice_MBAP[0][1]
        self.mbap.length = pairwice_MBAP[0][2]
        self.mbap.unit_id = pairwice_MBAP[0][3] 
        pairwice_MBAP.pop(0)
        return self.mbap                  
    
    def fuzz_field_mbap(self,pdu,slave):       
        """ 
        testing single fields (defaults) and Combinatorial=two-way/pair-wise
        is define fuzz_session.fuzz_session.test_field_MBAP=['transId', 'protoId', 'len','unitId', 'Combinatorial']
        tmp_test_list= is list of list of test case vector e.g mbap.transaction_id ,
        mbap.protocol_id,mbap.length,mbap.unit_id 
        unitID :to a MODBUS/TCP device is addressed using its IP address; therefore, 
        the MODBUS Unit Identifier is useless. The value 0xFF has to be used
        The value 0 is also accepted to communicate directly

        """
        lof=list_of_fuzz()  
        tcc=test_case_coverage()
        function_code, = struct.unpack(">B", pdu[0])
        query = modbus_tcp_b.TcpQuery_b()
        mbap = modbus_tcp_b.TcpMbap_b()                                                               
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_MBAP[:]
        test_field = fuzz_session.fields_of_list[0]      
        lgr.info('\t testing MBAP Field % r ' % test_field)
       
        if test_field == 'transId':   
            if len(fuzz_session.lib_of_MBAP_transid)==0 :                                             
               fuzz_session.lib_of_MBAP_transid=lof.lib_of_MBAP_transid(0,65535)                     #not short, dumpl eleme, ..                      
            mbap.transaction_id= fuzz_session.lib_of_MBAP_transid[0] 
            mbap.protocol_id =0
            mbap.length =  len(pdu)+1
            mbap.unit_id  = slave
            fuzz_session.lib_of_MBAP_transid.pop(0)                                                  #del item  index 0
            #fuzz_session.lib_of_MBAP_transid.append(fuzz_session.lib_of_MBAP_transid.pop(0))        #shift a list         

        elif test_field == 'unitId':           
            mbap.transaction_id=1
            mbap.protocol_id =0   
            mbap.length =  len(pdu)+1
            mbap.unit_id =fuzz_session.lib_of_MBAP_Unit_id[0]
            fuzz_session.lib_of_MBAP_Unit_id.append(fuzz_session.lib_of_MBAP_Unit_id.pop(0))         # case test MBAP more FC
                   
        elif test_field == 'len':
            mbap.transaction_id=1 
            mbap.protocol_id = 0                                                                      
            mbap.length=fuzz_session.lib_of_MBAP_length[0]         
            mbap.unit_id  = slave
            adu= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
            lgr.info(' : %d' % mbap.length )
            fuzz_session.lib_of_MBAP_length.append(fuzz_session.lib_of_MBAP_length.pop(0))
                                         
        elif test_field == 'protoId': 
            mbap.transaction_id=1
            mbap.protocol_id =fuzz_session.lib_of_MBAP_protocol[0]
            mbap.length =  len(pdu)+1
            mbap.unit_id  = slave
            fuzz_session.lib_of_MBAP_protocol.append(fuzz_session.lib_of_MBAP_protocol.pop(0))            #shift a list
        
        #Combinatorial testing   as > big-endian  
        elif test_field == 'Combinatorial': 
            mbap=self.mbap_custom()                                                                                                                  
            lgr.info(': %d,%d,%d,%d' % (mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id))
         
        else:
            pass
            lgr.warn('Choice Error,all fields = 0x00')

        lgr.info('transaction id is :  % d , 0x%02X ..' % (mbap.transaction_id,mbap.transaction_id))
        #counters   
        fuzz_session.field1_valid += 1       

        #Check   protocol_id, length, unit_id 
        if mbap.protocol_id !=0:           
           lgr.warn('protocol_id is invalid:  % d , 0x%02X ..' % (mbap.protocol_id,mbap.protocol_id))
           fuzz_session.field2_invalid += 1
        
        else :
            lgr.info('protocol_id is valid:  % d , 0x%02X ..' % (mbap.protocol_id,mbap.protocol_id))
            fuzz_session.field2_valid += 1

        # length is invalid When !=len(pdu)+1 
        if mbap.length <6 or mbap.length ==0 or mbap.length!=len(pdu)+1 :
            
            lgr.warn('length is invalid: % d , 0x%02X ..' % (mbap.length,mbap.length))
            fuzz_session.field3_invalid += 1
        
        else :
            lgr.info('length is valid: %d , 0x%02X ..' % (mbap.length,mbap.length))
            fuzz_session.field3_valid += 1

        #The value 0 is also accepted to communicate directly , The value 0xFF has to be used
        lgr.info('unitID is :  % d , 0x%02X ..' % (mbap.unit_id,mbap.unit_id))
        fuzz_session.field4_valid += 1
    
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([mbap.transaction_id ,mbap.protocol_id,mbap.length,mbap.unit_id ]) 
        
        #check - for last item of list --fuzz_session.l_lib_of_MBAP_transid=
        if  (len(fuzz_session.lib_of_MBAP_transid)==1 and test_field=='transId') \
            or (mbap.protocol_id ==fuzz_session.l_lib_of_MBAP_protocol and test_field=='protoId') \
            or (mbap.unit_id==fuzz_session.l_lib_of_MBAP_Unit_id and test_field=='unitId') \
            or (mbap.length==fuzz_session.l_lib_MBAP_length and test_field=='len'):
            
            if test_field=='transId':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_MBAP,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
            
            if test_field=='protoId':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_MBAP,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 

            if test_field=='len':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_MBAP,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=65535) 
        
            if test_field=='unitId':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_MBAP,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=256) 
    
            tcc.test_case (function_code,test_field,fuzz_session.test_field_MBAP,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            #l.insert(newindex, l.pop(oldindex))            
            fuzz_session.fields_of_list.pop(0)
        
        if (len(pairwice_MBAP)==0 and test_field=='Combinatorial'):            
            
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field4_valid,fuzz_session.field4_invalid])
            tcc.test_case (function_code,test_field,fuzz_session.test_field_MBAP, np.array(fuzz_session.tmp_test_list))
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_MBAP,fuzz_session.tmp_list_of_case,t=65535)
            fuzz_session.tmp_test_list=[] 
            fuzz_session.fields_of_list.pop(0)              #removes the item /'2-way
            self.reset()
                
        if len(fuzz_session.fields_of_list)==0:
           fuzz_session.flag_reguest=False                 #Stop reguest and fuzzer 
        
        return  struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )

#------------------------------------------------------------------------------------------------------------#
#This class fuzzing illegal packet len (dumplicate ADU/PDU, Remove PDU, Gross ? len.mbap and follow len PDU)
#------------------------------------------------------------------------------------------------------------#

class test_illegal_PDU (TestQueriesSerialFC):
    
    dumplicate_number=[]
    lof=list_of_fuzz()

   
    def __init__(self,adu="",mbap="",pdu=""):
        '''
        pairs OF COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
        integer_boundaries for byte count REG: quantity_of_x_list)
        
        pairsfind=pairs_address_qua()-- PAIRWISE test 
        - ---------------------------    Set PAIRWISE test Initializes  for address vs quantity   ----------------------
        Test case Initializing for FC01 --------- : 5254 in pairwice_READ_COILS.size 
        Test case Initializing for FC02 --------- : .... 
        Test case Initializing for FC03 --------- : ....
        Test case Initializing for FC04 --------- : ....

        ''' 
        
        lof=list_of_fuzz()
        self.QC=lof.list_quantity_for_cart_prod(1968,2000,2)
        self.QH=lof.list_quantity_for_cart_prod(121,125,2)
        self.A_CO=lof.list_address_for_cart_prod(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS,2)
        self.A_DI=lof.list_address_for_cart_prod(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN,2)
        self.A_IR=lof.list_address_for_cart_prod(fuzz_session.MIN_IN_REG,fuzz_session.MAX_IN_REG,2)       
        self.A_HR=lof.list_address_for_cart_prod(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG,2)
       
        self.mbap=mbap
        self.pdu=pdu
        self.adu=adu
        self.output_value=1
        self.Mult_output_value=[]

        """library of static fuzz VALUE of length"""
        self.illegal_pdu_len=[]

        """ Dumplicate test Read and Write FC """
        self.FC_dumplicate_ADU=[1,2,3,4,5,6,15,16]

        """ len of ADU for FC=1,2,3,4,5,6 """
        self.len_ADU=12

        """load first time list of test illegal PDU length of char"""
        if fuzz_session.flag_init_illegal_pdu_len==True :     
            fuzz_session.illegal_pdu_len=self.int_lof(self.illegal_pdu_len)
            fuzz_session.flag_init_illegal_pdu_len=False
        
    def int_lof(self,illegal_pdu_len):
        """ The def implements library of static fuzz VALUE of length"""    
         
        illegal_pdu_len=list_of_fuzz().illegal_len_list()
        fuzz_session.illegal_pdu_len= illegal_pdu_len
        fuzz_session.len_of_list=len(illegal_pdu_len)
        return  illegal_pdu_len
            

    def list_of_dumpl_number(self):
        """ 
        The def implements library of static fuzz VALUE (interesting up to 256 and 512,512,1024,2048,4096) 
        of number Dumplicate send ADU
        """    
        
        return list_of_fuzz().lib_interesting_256_exte()
       
    def mbap_custom(self,pdu):
        """
        create mbap OBJECT custom
        """

        query = modbus_tcp_b.TcpQuery_b() 
        mbap1 = modbus_tcp_b.TcpMbap_b()                      
        mbap1.transaction_id = query.get_transaction_id_b()
        mbap1.protocol_id = 0
        mbap1.length = len(pdu)+1
        mbap1.unit_id = 1 
        return mbap1      
    
    
    def mbap_zero(self,pdu):
        """
        create mbap OBJECT custom zero all 
        """
        
        query = modbus_tcp_b.TcpQuery_b()
        mbap0 = modbus_tcp_b.TcpMbap_b()                             
        mbap0.transaction_id = 0
        mbap0.protocol_id = 0
        mbap0.length =0
        mbap0.unit_id = 0
        return mbap0 
   
    
    def fuzz_payload(self,pdu):
        '''
        This functions fuzzes a message Modbus, test_dumplicate_ADU, test_illegal_len_PDU (not spec), 
        remove PDU from packet/
        global define in start fuzz_session.fp= ['repeat PDU' --not use,'remove','test_dumplicate_ADU,'test_illegal_PDU']
        '''    

        fuzz_type = fuzz_session.fp[0]
        lgr.info('Fuzzing a payload : ' + fuzz_type)
       
        if fuzz_type=='test_dumplicate_ADU' :
            adu,pdu=self.fuzz_payload_func[fuzz_type](self,pdu)
                                                          
        elif fuzz_type=='test_illegal_len_PDU' :
            adu,pdu=self.fuzz_payload_func[fuzz_type](self,pdu)     
                        
        elif fuzz_type=='remove':  
            adu,pdu=self.fuzz_payload_func[fuzz_type](self,pdu)
            #fuzz_session.fp.append(fuzz_session.fp.pop(0))
           
        
        else :
            lgr.info('error')    

        return adu,pdu
                
   
    def payload_remove(self,pdu):
       """
        This function removes a data from  PDU (not FC ) from the message Modbus
        payload_remove  --newdata = olddata[:start] + olddata[end:]
        len(pdu)-1 is data NOT fc
        Function code      1 Byte    0x01/0x02
        Starting Address   2 Bytes   0x0000 to 0xFFFF
        Quantity of coils  2 Bytes   1 to 2000 (0x7D0)
        fuzz_session.byte_remove=0  defaults

       """
       adu = ""
       lgr.info('remove fields of data PDU, Datasize: %d' %((len(pdu))-1))
       payloads_pdu = []
       if len(pdu)-1==fuzz_session.byte_remove or len(pdu)-1==0:
            #shift a list, next fuzz operation
            fuzz_session.fp.append(fuzz_session.fp.pop(0))
            fuzz_session.byte_remove=0
            fuzz_session.flag_reguest=False             #Stop reguest, next fc

       fuzz_session.byte_remove +=1
       new_pdu=pdu[0:fuzz_session.byte_remove]         # i=1 start and i=4 e.g FC01 PDU 
       lgr.info('SendDatasize : %d' % len(new_pdu[1:])) 
       pdu=new_pdu
       return adu,pdu
    


    def test_illegal_len_PDU(self,pdu): 
       '''
       This function after legal PDU inserts a heuristic illegal length random or one char PDU and send 
       send after PDU, len of random string /ascii/all char/only alpanum/only one char
       fuzz_test_PDU= ['test_illegal_len_PDU','test_dumplicate_ADU','remove']--remove /replace
       attack_PDU=['attack_randByte','attack_inter_byte'] 
       fuzz_session.fp= ['test_illegal_len_PDU','test_dumplicate_ADU','remove']--replace --fuzz_test_PDU
       fuzz_session.attack_byte_PDU=['attack_randByte','attack_inter_byte']    

       '''  
       global fuzz_session                           
       r=0
       length=0 
       adu= ""
       fuzz_test_PDU = fuzz_session.fp[0]
       attack_PDU= fuzz_session.attack_byte_PDU[0]
       lgr.info('Fuzz test attack_PDU: %r '%attack_PDU)                      
       function_code, = struct.unpack(">B", pdu[0])                                           
       lgr.info('The function_code is: % r ' % function_code) 

       if function_code == Diagnostics :
           lgr.info('sub code is:  % r'% ByteToHex(pdu[1:3]))
           DiagAndsubcode = pdu[0:3]                                                         
           pdu=DiagAndsubcode
           
       else  : 
           pass                                  
                                    
       if attack_PDU =='attack_randByte' :
            pdu=self.test_attack_randByte(pdu)
            #fuzz_session.fp.insert(len(fuzz_session.fp)+1,fuzz_session.fp.pop(0))
       
       elif  attack_PDU =='attack_inter_byte' :
            pdu=self.test_attack_interByte(pdu)

       else  :lgr.info('not fuzz testing');pass

       if len(pdu)>253 or len(pdu)==0:
            lgr.warn('total len PDU request out of spec .. !! : %d bytes' % len(pdu))
       else :
            lgr.info('total len PDU request in of spec : %d bytes' % len(pdu))
            
       return adu,pdu

    def test_attack_randByte(self,pdu):
        '''
        This function after legal PDU inserts a heuristic illegal length random or one char PDU and send 
        send after PDU, len of random string /ascii/all char/only alpanum/only one char
        if fuzz_session.illegal_pdu_len list is last item ,  #shift a list, next fuzz 'attack_inter_byte
        '''
        r=random.randint(0,100)
       
        attacksize=fuzz_session.illegal_pdu_len[fuzz_session.item_list]
        if attacksize==fuzz_session.illegal_pdu_len[-1]:
            fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))                    #shift a list, next fuzz 'attack_inter_byte']
            fuzz_session.item_list=0 

        fuzz_session.item_list += 1
        lgr.info('attacksize : %d' % attacksize)                 
            
        if r<35:                                                                      
            lgr.info('all char')
            pdu += ''.join([chr(random.randint(0,255)) for i in xrange(0,attacksize)]) 
        elif r<70:                                         
            lgr.info('ascii only')
            pdu += ''.join([chr(random.randint(0,128)) for i in xrange(0,attacksize)])
        elif r<80:     
            lgr.info('only alpanummeric')
            pdu += ''.join([chr((random.randint(0,96))+32) for i in xrange(0,attacksize)])                              
        else:                                             
            c=random.randint(0,96)+32
            lgr.info('patterns one char : %r , 0x%02X ' % (c,c))
            attackstring = ''.join( [chr(c) for i in xrange(0,attacksize)])
            pdu += attackstring
                       
        return pdu  


    def test_attack_interByte(self,pdu):
        '''
        This function after legal PDU inserts (attacksize) a heuristic illegal length intersting byte (FE,FF,00, exception ,...) in defines.py
        size  is value *  inter byte ,and attackstring[:65555] bountery +-10 
        fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))   
        index >>fuzz_session.item_list_hex, fuzz_session.item_list
        if  intersting byte >1 byte, adjucts in len                 
        '''
        urlist_len=len(fuzz_session.bytehex)-1
        size=fuzz_session.illegal_pdu_len[fuzz_session.item_list]
        attackstring=fuzz_session.illegal_pdu_len[fuzz_session.item_list]*fuzz_session.bytehex[fuzz_session.item_list_hex]
        #if  intersting byte >1 byte, adjucts in len  
        attackstring=attackstring[:fuzz_session.illegal_pdu_len[fuzz_session.item_list]]
        if len(attackstring)>65535:attackstring=attackstring[:65545] # bountery +-10

        lgr.info('size of: %d and test intersting bytes: %r' % (size,ByteToHex(fuzz_session.bytehex[fuzz_session.item_list_hex])))
        lgr.info('attacksize : %d' % len(attackstring))
        lgr.info('attackstring message first 260 Byte: %r' % ByteToHex(attackstring[:260]))
        #last item 
        if size==fuzz_session.illegal_pdu_len[-1] and fuzz_session.bytehex.index(fuzz_session.bytehex[fuzz_session.item_list_hex])==urlist_len: 
            fuzz_session.item_list=0;fuzz_session.item_list_hex=0            
            #shift a list, next fuzz operation 
            fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))                   
            fuzz_session.fp.append(fuzz_session.fp.pop(0))
            lgr.info(' ......... Change testing ... ...' )
            
        elif fuzz_session.bytehex.index(fuzz_session.bytehex[fuzz_session.item_list_hex])==urlist_len: 
           fuzz_session.item_list_hex=0;fuzz_session.item_list += 1 #next len
           
        else : fuzz_session.item_list_hex += 1  
       
        pdu += attackstring
        return pdu 

    

    def send_dumplicate (self,pdu,pdu_next,item):
        '''
        IN THE END  SEND -RANDOM for all pairwice_address vs quantity (interesting)
        return self.adu,(pdu+dumplicate_message_zero+)
        return self.adu,(pdu+dumplicate_message)
        return self.adu,(pdu+dumplicate_message_zero+dumplicate_message+(dumplicate_message_zero+dumplicate_message)......)

        '''

        mbap=self.mbap_custom(pdu_next)                                            
        mbap1= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )          
        #mbap zero message
        mbap0=self.mbap_zero(pdu_next)
        mbap0= struct.pack(">HHHB", mbap0.transaction_id, mbap0.protocol_id, mbap0.length, mbap0.unit_id )
        r=random.randint(0,100)
                    
        if r<35:
            dumplicate_message_zero_mbap=(item*(mbap0+pdu_next))
            lgr.info('send  dumplicate_number %d,message_zero_mbap: %r ' % (item,ByteToHex(mbap0+pdu_next)))          
            return self.adu,(pdu+dumplicate_message_zero_mbap)
        elif r<70:         
            dumplicate_message=(item*(mbap1+pdu_next))
            lgr.info('send  dumplicate_number %d,dumplicate_message: %r ' % (item,ByteToHex(mbap1+pdu_next)))           
            return   self.adu,(pdu+dumplicate_message)
        else: 
            dumplicate_message=(item*((mbap0+pdu_next)+(mbap1+pdu_next)))
            lgr.info('send  dumplicate_number %d,dumplicate_message_zero_mbap+dumplicate_message: %r ' % (item,ByteToHex((mbap0+pdu_next)+(mbap1+pdu_next))))            
            return self.adu,(pdu+dumplicate_message)    

    def test_dumplicate_ADU(self,pdu):
        '''
        This function inserts one or more dumplecate ADU in message Modbus and send
        Dumplicate test Read and Write FC 
        for self.FC_dumplicate_ADU=[1,2,3,4,5,6,15,16]
        self.QC=num quantity_of_x_list for coils

        pairwice_READ_COILS=np.array([], dtype=np.int16)..
        dumplicate_message: with interesting address vs quantity
        dumplicate_message_zero=mbap0+pdu_next
        fuzz_session.dumplicate_number, value message in ADU
         
        '''
        global slave,pairwice_WRITE_SINGLE_REGISTER,pairwice_READ_COILS,pairwice_READ_INPUT_REGISTERS,pairwice_READ_HOLDING_REGISTERS,pairwice_READ_DISCRETE_INPUTS,pairwice_WRITE_SINGLE_COIL                                     
        pairsfind=pairs_address_qua()
        #extract function_code from support fc    
        function_code, = struct.unpack(">B", pdu[0])                           
        lgr.info('The function_code is % d'  % function_code)
        
        while True:
            #change support FC test
            
            if len(fuzz_session.FC_dumplicate_ADU)==0 :
                fuzz_session.FC_dumplicate_ADU=self.FC_dumplicate_ADU
                #l.insert(newindex, l.pop(oldindex)) first element go to end
                fuzz_session.fp.insert(len(fuzz_session.fp)+1,fuzz_session.fp.pop(0))
                lgr.info('.........change test of ...... ' )
                # get_transaction_id_ with next transaction synchronization
                mbap=self.mbap_custom(pdu)           
                break
                

            #Case READ COILS as next Multiple Modbus messages (ADU)
            if  READ_COILS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 01: READ_COILS as next PDU')
                #Set PAIRWISE test Initializes 
                if  pairwice_READ_COILS.size==0:
                    pairwice_READ_COILS=pairsfind.findPairs(self.A_CO,self.QC,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()                                          
                    
                fuzz_session.starting_address=pairwice_READ_COILS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_COILS[0][1]
                pdu_next= struct.pack(">BHH", READ_COILS, fuzz_session.starting_address, fuzz_session.quantity_of_x)
                
                lgr.info('Coils address: %d ..0x%02X and quantity %d . 0x%02X ' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))                 
                item=fuzz_session.dumplicate_number[0]
                # del line of np table and rotete list of dumplicate
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)
                #next FC_dumplicate_ADU
                if pairwice_READ_COILS.size==0:fuzz_session.FC_dumplicate_ADU.remove(READ_COILS);lgr.info('-----FC 01: READ_COILS as next PDU-Done')                     
                return self.send_dumplicate (pdu,pdu_next,item)       
        
            elif READ_DISCRETE_INPUTS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 02: READ_DISCRETE_INPUTS as next PDU')
                
                if pairwice_READ_DISCRETE_INPUTS.size==0:
                    #pairwice_READ_DISCRETE_INPUTS=np.array(list(itertools.product(self.A_DI,self.QC)))
                    pairwice_READ_DISCRETE_INPUTS=pairsfind.findPairs(self.A_DI,self.QC,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()                 
                
                lgr.info('Test case Initializing : %d '% len(pairwice_READ_DISCRETE_INPUTS))
                                
                fuzz_session.starting_address=pairwice_READ_DISCRETE_INPUTS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_DISCRETE_INPUTS[0][1]
                pdu_next= struct.pack(">BHH", READ_DISCRETE_INPUTS, fuzz_session.starting_address, fuzz_session.quantity_of_x)

                lgr.info('DISCRETE_INPUTS address : %d ..0x%02X and  quantity: %d..0x%02X .' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))                                
                item=fuzz_session.dumplicate_number[0]
                # del line of np table and rotete list of dumplicate
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_DISCRETE_INPUTS=np.delete(pairwice_READ_DISCRETE_INPUTS, 0, 0)
                #next FC_dumplicate_ADU
                if pairwice_READ_DISCRETE_INPUTS.size==0:fuzz_session.FC_dumplicate_ADU.remove(READ_DISCRETE_INPUTS);lgr.info('------FC 02: READ_DISCRETE_INPUTS as next PDU-Done')                 
                return self.send_dumplicate (pdu,pdu_next,item)  
         
            elif READ_HOLDING_REGISTERS  in  fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 03: READ_HOLDING_REGISTERS as next PDU')
                
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                    pairwice_READ_HOLDING_REGISTERS=pairsfind.findPairs(self.A_HR,self.QH,fuzz_session.MAX_HO_REG,fuzz_session.MIN_HO_REG)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()
            
                
                fuzz_session.starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                pdu_next= struct.pack(">BHH", READ_HOLDING_REGISTERS, fuzz_session.starting_address, fuzz_session.quantity_of_x) 
                
                lgr.info('READ_HOLDING_REGISTERS address: %d ..0x%02X and quantity: %d ..0x%02X' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
               
                item=fuzz_session.dumplicate_number[0]
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                               
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                    fuzz_session.FC_dumplicate_ADU.remove(READ_HOLDING_REGISTERS)
                    lgr.info('-------FC 03: READ_INPUT_REGISTERS as next PDU-Done') 
               
                return self.send_dumplicate (pdu,pdu_next,item)                               
                   

            elif READ_INPUT_REGISTERS in fuzz_session.FC_dumplicate_ADU  :
                lgr.info('FC 04: READ_INPUT_REGISTERS as next PDU')
                if pairwice_READ_INPUT_REGISTERS.size==0:
                    pairwice_READ_INPUT_REGISTERS=pairsfind.findPairs(self.A_IR,self.QH,fuzz_session.MAX_IN_REG,fuzz_session.MIN_IN_REG)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()
                
                fuzz_session.starting_address=pairwice_READ_INPUT_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_INPUT_REGISTERS[0][1]
                pdu_next= struct.pack(">BHH", READ_INPUT_REGISTERS, fuzz_session.starting_address, fuzz_session.quantity_of_x)
                lgr.info('READ_INPUT_REGISTERS address: %d .0x%02X quantity: %d..0x%02X..' %(fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                 
                item=fuzz_session.dumplicate_number[0]

                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_INPUT_REGISTERS=np.delete(pairwice_READ_INPUT_REGISTERS, 0, 0)
               
                if pairwice_READ_INPUT_REGISTERS.size==0:fuzz_session.FC_dumplicate_ADU.remove(READ_INPUT_REGISTERS)
               
                return self.send_dumplicate (pdu,pdu_next,item)

            #ok done    
            elif WRITE_SINGLE_COIL in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 05: WRITE_SINGLE_COIL as next PDU')
                
                if pairwice_WRITE_SINGLE_COIL.size==0:                   
                    pairwice_WRITE_SINGLE_COIL=np.array(self.A_CO)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number() 
               
                starting_address=pairwice_WRITE_SINGLE_COIL[0]
                value='0xff00'                                            #int 65280               
                fuzz_session.starting_address=starting_address
                fuzz_session.quantity_of_x='0xff00'
                pdu_next= struct.pack(">BHH", WRITE_SINGLE_COIL, fuzz_session.starting_address,int(0xff00))
                lgr.info('Coils address: %d .0x%02X  write value:%r  ' % (starting_address,starting_address,value))
                
                item=fuzz_session.dumplicate_number[0]

                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_WRITE_SINGLE_COIL=np.delete(pairwice_WRITE_SINGLE_COIL, 0, 0)# del line of np table
               
                if pairwice_WRITE_SINGLE_COIL.size==0:fuzz_session.FC_dumplicate_ADU.remove(WRITE_SINGLE_COIL)
                return self.send_dumplicate (pdu,pdu_next,item)  
               
            elif WRITE_SINGLE_REGISTER in fuzz_session.FC_dumplicate_ADU  :
                lgr.info('FC 06: WRITE_SINGLE_REGISTER as next PDU')
                if pairwice_WRITE_SINGLE_REGISTER.size==0:
                    #list of coils only not pairwice
                    pairwice_WRITE_SINGLE_REGISTER=np.array(self.A_HR)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()  
                
                fuzz_session.starting_address=pairwice_WRITE_SINGLE_REGISTER[0]
                fuzz_session.value='0x0001'
                pdu_next= struct.pack(">BHH", WRITE_SINGLE_REGISTER,fuzz_session.starting_address,int(0x0001))                                              
                
                lgr.info('address valid: %d .0x%02X write value:%r ' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.value))
                                                                                             
                item=fuzz_session.dumplicate_number[0]

                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_WRITE_SINGLE_REGISTER=np.delete(pairwice_WRITE_SINGLE_REGISTER, 0, 0)# del line of np table
               
                if pairwice_WRITE_SINGLE_REGISTER.size==0:fuzz_session.FC_dumplicate_ADU.remove(WRITE_SINGLE_REGISTER)  
               
                return self.send_dumplicate (pdu,pdu_next,item)  
                       
            elif WRITE_MULTIPLE_COILS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 15: WRITE_MULTIPLE_COILS as next PDU')
                
                if  pairwice_READ_COILS.size==0 :
                        #pairwice_READ_COILS=np.array(list(itertools.product(self.A_CO,self.QC)))
                        pairwice_READ_COILS=pairsfind.findPairs(self.A_CO,self.QC,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS)   
                        fuzz_session.dumplicate_number=self.list_of_dumpl_number()
                
                fuzz_session.starting_address=pairwice_READ_COILS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_COILS[0][1]
                #list of output value, each frame in spec 
                if fuzz_session.quantity_of_x>1968:self.Mult_output_value=1968*[self.output_value]
                    
                else :self.Mult_output_value=fuzz_session.quantity_of_x*[self.output_value]
                byte_count = len(self.Mult_output_value) / 8
                if byte_count>255:byte_count =255

                lgr.info('starting address: %d .0x%02X , quantity_of_x: %d .0x%02X ' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                lgr.info('byte_count: %d .0x%02X ' % (byte_count,byte_count))
                
                pdu_next = struct.pack(">BHHB", WRITE_MULTIPLE_COILS , fuzz_session.starting_address, fuzz_session.quantity_of_x,byte_count)
                if ((len(self.Mult_output_value)) % 8) > 0:
                        byte_count += 1
                
                i, byte_value = 0, 0
                for j in self.Mult_output_value:
                    if j > 0:
                        byte_value += pow(2, i)
                    if i == 7:
                        pdu_next += struct.pack(">B", byte_value)
                        i, byte_value = 0, 0
                    else:
                        i += 1
                if i > 0:
                    pdu_next += struct.pack(">B", byte_value)
                
                item=fuzz_session.dumplicate_number[0]
                               
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)# del line of np table
                
                if pairwice_READ_COILS.size==0:fuzz_session.FC_dumplicate_ADU.remove(WRITE_MULTIPLE_COILS)                 
                return self.send_dumplicate (pdu,pdu_next,item)

            elif WRITE_MULTIPLE_REGISTERS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 16: WRITE_MULTIPLE_REGISTERS as next PDU')
                    
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                    #pairwice_READ_HOLDING_REGISTERS=np.array(list(itertools.product(self.A_HR,self.QH)))
                    pairwice_READ_HOLDING_REGISTERS=pairsfind.findPairs(self.A_HR,self.QH,fuzz_session.MAX_HO_REG,fuzz_session.MIN_HO_REG)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()
            
                fuzz_session.starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]                                
                #list of output value, packet in spec
                if fuzz_session.quantity_of_x>121:self.Mult_output_value=123*[self.output_value] 
                               
                else :self.Mult_output_value=fuzz_session.quantity_of_x*[self.output_value]
                byte_count = 2 * len(self.Mult_output_value)
                if byte_count>255:byte_count =255               
                pdu_next = struct.pack(">BHHB", WRITE_MULTIPLE_REGISTERS, fuzz_session.starting_address, fuzz_session.quantity_of_x,byte_count)
                                
                for j in self.Mult_output_value:
                    pdu_next += struct.pack(">H", j)

                lgr.info('starting address: %d .0x%02X quantity_of_x: %d .0x%02X' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                lgr.info(' byte_count: %d ..0x%02X'  % (byte_count,byte_count))
                item=fuzz_session.dumplicate_number[0]
                
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                
                if pairwice_READ_HOLDING_REGISTERS.size==0:fuzz_session.FC_dumplicate_ADU.remove(WRITE_MULTIPLE_REGISTERS )  
               
                return self.send_dumplicate (pdu,pdu_next,item)
            else:
                lgr.info('Error/Empty/FClist_dumplicate_ADU  : %s' %fuzz_session.FC_dumplicate_ADU)
                return  self.adu,pdu 
        return self.adu,pdu          

   
    # A map from payload fuzz type to payload fuzz function
    fuzz_payload_func = {}
    fuzz_payload_func['test_dumplicate_ADU'] = test_dumplicate_ADU     #dumple ADU(mbap+PDU) in the MESSAGE -
    fuzz_payload_func['remove'] = payload_remove                       #removes a payload pdu from the packet-
    #fuzz_payload_func['test_dumplicate_PDU'] = payload_message        #Fuzzig a dumple pdu /not implementation
    fuzz_payload_func['test_illegal_len_PDU'] = test_illegal_len_PDU   #insert random byte after PDU 

#------------------------------------------------------------------------------------
# Fuzzig none, random valid  message send
#------------------------------------------------------------------------------------
class fuzzer_None(object):
    """ 
    Fuzzig none, case fuzz_session.priority=4
    None Fuzzing, def num_of_request=1000 for FC
    """
        
    def __init__(self):
        pass
                    
    def fuzz_field_None(self,pdu):
        adu=""
        if fuzz_session.non_f_num_of_request ==fuzz_session.normal_request-1:
            fuzz_session.flag_reguest=False;fuzz_session.non_f_num_of_request=-1
        self.case_of_fields(pdu)
        return adu,pdu   

    
    def case_of_fields(self,pdu):
       
        self.function_code, = struct.unpack(">B", pdu[0])
        lgr.info('The function_code is % s'  % self.function_code)
        fuzz_session.non_f_num_of_request  += 1
        
        while True:
            
            try:

                if self.function_code == READ_COILS :
                    lgr.info('FC 01: READ_COILS ')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info('starting_address: %d,quantity_of_x: %d' % (starting_address, quantity_of_x))              
                    break

                elif self.function_code == READ_DISCRETE_INPUTS :    
                    lgr.info('FC 02: READ_DISCRETE_INPUTS')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info(' starting_address: %d,quantity_of_x:%d' % (starting_address, quantity_of_x))                
                    break
                
                elif self.function_code == READ_HOLDING_REGISTERS :    
                    lgr.info('FC 03: READ_HOLDING_REGISTERS')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info(': %d,%d' % (starting_address, quantity_of_x))
                    break

                elif self.function_code == READ_INPUT_REGISTERS :    
                    lgr.info('FC 04: READ_INPUT_REGISTERS')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info(': %d,%d' % (starting_address, quantity_of_x))
                    break    

                elif self.function_code == WRITE_SINGLE_COIL :    
                    lgr.info('FC 05: WRITE SINGLE COIL')
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    lgr.info('starting_address: %d,output_value: %d' % (starting_address,output_value ))
                    break    
                
                elif self.function_code == WRITE_SINGLE_REGISTER :    
                    lgr.info('FC 06: WRITE_SINGLE_REGISTER')
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    lgr.info('starting_address: %d,output_value: %d' % (starting_address,output_value ))
                    break 

                elif self.function_code == WRITE_MULTIPLE_COILS :    
                    lgr.info('FC 15: WRITE_MULTIPLE_COILS')
                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    lgr.info('starting_address: %d,quantity_of_x: %d,byte_count: %d' % (starting_address, quantity_of_x, byte_count ))
                    break     

                elif self.function_code == WRITE_MULTIPLE_REGISTERS :    
                    lgr.info('FC 16: WRITE_MULTIPLE_REGISTERS')
                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    lgr.info('starting_address: %d,quantity_of_x: %d,byte_count: %d' % (starting_address, quantity_of_x, byte_count ))
                    break     
                
                elif self.function_code == Mask_Write_Register :    
                    lgr.info('FC 22: Mask Write Register')
                    starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
                    lgr.info('starting_address:%d,and_mask: %d,or_mask%d' % (starting_address, and_mask, or_mask))
                    break 

                elif self.function_code == Read_Write_Multiple_Registers :    
                    lgr.info('FC 23: Read_Write_Multiple_Registers')
                    read_starting_address, quantity_to_Read, write_starting_address, quantity_to_Write,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
                    lgr.info('read_starting_address: %d,quantity_to_Read: %d,write_address: %d,quantity_to_Write: %d,write_byte_count: %d' % (read_starting_address, quantity_to_Read, \
                    write_starting_address, quantity_to_Write,write_byte_count))
                    break 


                elif self.function_code == Read_File_record:
                    lgr.info('FC 20: Read_File_record')
                    Byte_Count,Reference_Type,File_number,File_record,Record_length=struct.unpack(">BBHHH", pdu[1:9])
                    lgr.info('Byte_Count: %d,Reference_Type: %d,File_number: %d,File_record: %d,Record_length: %d' % (Byte_Count,Reference_Type,File_number,\
                    File_record,Record_length))
                    break

                elif self.function_code == Write_File_record:    
                    lgr.info('FC 21: Write_File_record ')
                    Data_length,Reference_Type,File_number,Write_record,Record_length= struct.unpack(">BBHHH", pdu[1:9])
                    lgr.info('Data_length: %d,Reference_Type: %d,File_number: %d,Write_record: %d,Record_length: %d' % (Data_length,Reference_Type,File_number,Write_record,Record_length))
                    break

                elif self.function_code == Read_FIFO_queue  :    
                    lgr.info('FC 24 : Read_FIFO_queue')
                    Pointer_address, = struct.unpack(">H", pdu[1:3])
                    lgr.info(': %d' % (Pointer_address))
                    break 
                
                elif self.function_code == Read_device_Identification  :    
                    lgr.info('FC 43 : Read_device_Identification')
                    mei_type,read_code,object_id = struct.unpack(">BBB", pdu[1:5])
                    lgr.info('mei_type: %d,read_code: %d,object_id: %d' % (mei_type,read_code,object_id))
                    break

                elif self.function_code == Diagnostics :    
                    lgr.info('FC 8 : Diagnostics ')               
                    fuzz_session.flag_test_FC08_pair=False
                    break 

                elif self.function_code == Read_Exception_Status :    
                    lgr.info('FC 7 : Read_Exception_Status/not parameters PDU ')
                    fuzz_session.flag_reguest=False                    
                    break

                elif self.function_code == Get_Comm_Event_Counter :    
                    lgr.info('FC 11 : Get_Comm_Event_Counter/not parameters PDU ')
                    fuzz_session.flag_reguest=False
                    break             
                
                elif self.function_code == Get_Comm_Event_Logs  :    
                    lgr.info('FC 12 : Get_Comm_Event_Logs / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break   
                
                elif self.function_code == Report_Slave_Id  :    
                    lgr.info('FC 17 : Report_Slave_Id / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break        
                else: 
                    lgr.info('Other function_code: %d ....' % self.function_code)
                    break  
            
            #default for detect error                                                                  
            except:                                                                                      
                   
                   lgr.warn('some error raise')
                   return pdu                  
            return  pdu           

    

class process():
               
    '''
    # Chooses an item from a list defined as priority:
    # [(item_1,priority_1), (item_2,priority_2),... ,(item_priority_n)]
    # where priority_i is the priority of choosing item_i
    #
    '''    
    def priority_choice(self,items):
      
       priority_choice = fuzz_session.priority
       for item, priority in items:
          if (priority==priority_choice) :
             return item
          item=0
       return item  
                   
    #------------------------------------------------------------#
    # When a new pdu is detected, the fuzzer also starts
    # a new session, i.e. # + Num of request
    #------------------------------------------------------------#
    def init_new_session(self,pdu,slave):
       #global fuzz_session,num_of_request
       #import fuzz_session 
       lgr.info('');F_session = Fuzz_session()                                                  
       fuzz_session.num_of_request += 1 
       lgr.info('\t New request ------> %d',fuzz_session.num_of_request)
       
       F_session.fuzz = self.priority_choice(test_suites_list) 
          
       if F_session.fuzz == 'test_message_PDU':
          lgr.info('Prepare to fuzz test format_message')
          adu,pdu=test_illegal_PDU().fuzz_payload(pdu) 
          return adu,pdu        
       elif F_session.fuzz == 'test_MBAP':
          lgr.info('Prepare to fuzz test fields in MBAP')
          adu=fuzz_test_MBAP().fuzz_field_mbap(pdu,slave)
          return adu,pdu         
       elif F_session.fuzz == 'test_field_PDU':
          lgr.info('Prepare fuzz test fields in PDU')
          adu,pdu=fuzzer_pdu().fuzz_field_pdu(pdu)
          return adu,pdu 
       elif F_session.fuzz == 'Not_fuzz':
          lgr.info('Prepare fuzz None')
          adu,pdu=fuzzer_None().fuzz_field_None(pdu)
          return adu,pdu
       elif F_session.fuzz == 'Serial_FC':
          lgr.info('Prepare Serial_FC')
          pass
                                                                                                                                                                                   
 #------------------------------------------------------------------------------------------------------------------------  
 #read  use function of modbus_tk, script modbus.py, def execute ( ......) , execute_f is similar in modbus_b.py my script
 #vector address and other  is first choice if choice 'Not_fuzz': Fuzzig none, original message send (random)
 #fuzz_session.priority=4
 #------------------------------------------------------------------------------------------------------------------------
class TestQueries(SetupAndTeardown,list_of_fuzz):
    global num_diagnostics_request,search_mode, fuzz_mode, MIN_COILS, MAX_COILS,MIN_IN_REG,MAX_IN_REG, MIN_DIS_IN,MAX_DIS_IN,MIN_HO_REG,MAX_HO_REG
    
    def __init__(self,address_COILS=1024,COILS_quantity=2,address_DIS_IN=1024,DIS_IN_quantity=2,address_HO_REG=1024,HO_REG_quantity=2,address_IN_REG=1024,IN_REG_quantity=2,output_value=1,record_length=2,file_number1=3,record_number=256):

        self.address_COILS = address_COILS
        self.COILS_quantity = COILS_quantity
        self.address_DIS_IN = address_DIS_IN
        self.DIS_IN_quantity = DIS_IN_quantity
        self.address_HO_REG = address_HO_REG 
        self.HO_REG_quantity = HO_REG_quantity
        self.Write_HO_REG_quantity= HO_REG_quantity
        self.address_IN_REG=address_IN_REG
        self.IN_REG_quantity = IN_REG_quantity
        self.output_value=1
        self.file_number1=file_number1
        self.file_number2=file_number1
        self.record_number=record_number
        self.record_length=record_length
        self.flag_reguest=True
        self.read_code =0x01
        self.object_id = 0x01

    """Check that read coil queries are handled correctly"""

    def test_readcoil(self):
            vector_address =(fuzz_session.MIN_COILS + fuzz_session.MAX_COILS )/2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % (vector_address,self.COILS_quantity))   
            #legal address of legal message 
            fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.COILS_quantity                
            for i in itertools.count():
                    # case - legal genarate randomize input test
                    if fuzz_session.priority==4 :                     
                        vector_address =random.randint(fuzz_session.MIN_COILS, fuzz_session.MAX_COILS);self.COILS_quantity = random.randint(1,2000)                     
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.COILS_quantity 
                                          
                    master1.execute_f(slave, READ_COILS,vector_address, self.COILS_quantity)                   
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)     
             
    
    """Test that response for read analog inputs (READ_INPUT_REGISTERS) function """
    def test_ReadAnalogInputs(self):
            vector_address =(fuzz_session.MIN_IN_REG+fuzz_session.MAX_IN_REG)/2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % (self.address_IN_REG,self.IN_REG_quantity))            
            fuzz_session.starting_address= vector_address
            fuzz_session.quantity_of_x=self.COILS_quantity
            for i in itertools.count():
                    ##case - legal genarate randomize input test 
                    if fuzz_session.priority==4 : 
                          vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);self.IN_REG_quantity = random.randint(1,125)
                          fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.IN_REG_quantity                       
                    master1.execute_f(slave,READ_INPUT_REGISTERS, vector_address,self.IN_REG_quantity )                                                                 
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)    
            
    """Test that response for read digital inputs function """ 
    def test_ReadDiscreteInputs(self):
            vector_address =(fuzz_session.MIN_DIS_IN+fuzz_session.MAX_DIS_IN)/2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % ( vector_address,self.DIS_IN_quantity ))   
            fuzz_session.starting_address=vector_address ;fuzz_session.quantity_of_x=self.DIS_IN_quantity
            
            for i in itertools.count():              
                    ##case - legal genarate randomize input test 
                    if fuzz_session.priority==4 : 
                        vector_address =random.randint(fuzz_session.MIN_DIS_IN, fuzz_session.MAX_DIS_IN);self.DIS_IN_quantity = random.randint(1,2000)
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.DIS_IN_quantity  
                    master1.execute_f(slave,READ_DISCRETE_INPUTS,vector_address, self.DIS_IN_quantity)                             
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)     
            
    """Test that response for read holding resister -READ_HOLDING_REGISTERS, function """ 
    def test_readhr(self):
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/2
            lgr.info('vector_address: %d , vector_quantity_of_x: %d' % (vector_address,self.HO_REG_quantity ))
            fuzz_session.starting_address=vector_address ;fuzz_session.quantity_of_x=self.HO_REG_quantity   
                      
            for i in itertools.count():                      
                    # case - legal genarate randomize input test 
                    if fuzz_session.priority==4 : 
                       vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);self.HO_REG_quantity = random.randint(1,123)
                       fuzz_session.starting_address=vector_address ;fuzz_session.quantity_of_x=self.HO_REG_quantity 

                    master1.execute_f(slave,READ_HOLDING_REGISTERS, vector_address, self.HO_REG_quantity )
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)        

    """Check that write WRITE_MULTIPLE_REGISTERS  queries are handled correctly/contiguous registers (1 to  123  registers"""  
    def test_WriteMultipleHr(self):
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/2          
            Mult_output_value=(2*self.HO_REG_quantity)*[self.output_value]
            lgr.info('vector_address: %d ,  vector_quantity_of_x: %d, Mult_output_value: %r ' % (vector_address,self.HO_REG_quantity,Mult_output_value))   
            fuzz_session.starting_address=vector_address
            fuzz_session.quantity_of_x=self.HO_REG_quantity
            for i in itertools.count():         
                    # case - legal genarate randomize input test  
                    if fuzz_session.priority==4 :
                        vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);self.HO_REG_quantity=random.randint(1,61)   
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.HO_REG_quantity
                        
                    master1.execute_f(slave, WRITE_MULTIPLE_REGISTERS , vector_address, output_value=(2*self.HO_REG_quantity)*[self.output_value])                                        
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)        
    
    """Check that write WRITE_MULTIPLE_COILS queries are handled correctly max 1968 value_out"""               
    def test_WriteMultipleCoils(self):
            vector_address =(fuzz_session.MIN_COILS + fuzz_session.MAX_COILS )/2                                          
            lgr.info('vector_address: %d , Mult_output_value: %d * [%d]' % (vector_address,self.COILS_quantity,self.output_value))
            fuzz_session.starting_address=vector_address
            fuzz_session.quantity_of_x=self.COILS_quantity    
            for i in itertools.count():  
                    if fuzz_session.priority==4 :
                        # case - legal genarate randomize input test  
                        vector_address =random.randint(fuzz_session.MIN_COILS, fuzz_session.MAX_COILS)
                        self.COILS_quantity=random.randint(1,1968)
                        fuzz_session.starting_address=vector_address;fuzz_session.quantity_of_x=self.COILS_quantity                  
                    master1.execute_f(slave, WRITE_MULTIPLE_COILS , vector_address , output_value=tuple([self.output_value]*self.COILS_quantity) )
                                  
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)        
    
    """Check that write HOLDING_REGISTERS queries are handled correctly"""
    def test_writesingleHr(self):
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/2
            lgr.info('vector_address: %d , output_value: %d' % (vector_address,self.output_value))              
            fuzz_session.starting_address=vector_address
            fuzz_session.output_value=self.output_value
            
            for i in itertools.count():                     
                    # case - legal genarate randomize input test
                    if fuzz_session.priority==4 :
                        vector_address=random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG)
                        fuzz_session.starting_address=vector_address
                    master1.execute_f(slave, WRITE_SINGLE_REGISTER ,vector_address, output_value=self.output_value)
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)         
    
    """Check that write one coil queries are handled correctly/Output Value  2 Bytes  0x0000 or 0xFF00"""                
    def test_writecoil(self):
            vector_address =(fuzz_session.MIN_COILS + fuzz_session.MAX_COILS )/2
            lgr.info('vector_address: %d , output_value: %d' % (vector_address,self.output_value))   
            fuzz_session.starting_address=vector_address 
            
            for i in itertools.count() :                                       
                    ##case - legal genarate randomize input test
                    if fuzz_session.priority==4 :  
                       vector_address =random.randint(fuzz_session.MIN_COILS, fuzz_session.MAX_COILS)
                       fuzz_session.starting_address=vector_address 
                    master1.execute_f(slave, WRITE_SINGLE_COIL, vector_address, output_value=self.output_value)
                    
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)
    
    """
    Read Fifo Queue  FC : 24 
    the query specifies the starting 4XXXX reference to be read from the FIFO queue
    Test that response for read ReadFifoQueueRequestEncode function
    In a normal response, the byte count shows the quantity of bytes to
    follow, including the queue count bytes and value register bytes
    (but not including the error check field).  The queue count is the
    quantity of data registers in the queue (not including the count register).
    If the queue count exceeds 31, an exception response is returned with an
    error code of 03 (Illegal Data Value).

    """
    def test_ReadFifoQueueRequestEncode(self):           
            vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/2
            for i in itertools.count():
                    handle  = ReadFifoQueueRequest(vector_address)
                    result  = struct.pack(">B",Read_FIFO_queue)+handle.encode()
                    response=master1.execute_fpdu(slave,result)                    
                    lgr.info('Answer >> Test Pointer_address %s response %r '  % (fuzz_session.Pointer_address,response,))                  
                    if fuzz_session.flag_reguest==False :
                        break
            fuzz_session.flag_reguest=True
            sleep(1.0)            

    """ Read File Record Request FC : 20   file_number: 0-0xffff  record_number:0-0x270f  record_length=N 2 byte
        Returns the contents of registers in Extended Memory file (6XXXXX) references
        The function can read multiple groups of references. The groups can be separate
        (non–contiguous), but the references within each group must be sequential.
        :params reference_type: Defaults to 0x06 (must be)
        :params file_number: Indicates which file number we are reading
        :params record_number: Indicates which record in the file -(starting address)
        :params record_data: The actual data of the record - 
        :params record_length: The length in registers of the record -(register count)
        :params response_length: The length in bytes of the record
    """    
    def test_ReadFileRecordRequestEncode(self):
            
            for i in itertools.count():
                record1  = FileRecord(file_number=0x01, record_number=0x01, record_length=0x02)
                record2  = FileRecord(file_number=0x02, record_number=0x02, record_length=0x04)
                record3  = FileRecord(file_number=0x03, record_number=0x03, record_length=0x02)
                record4  = FileRecord(file_number=0x04, record_number=0x04, record_length=0x04)
                
                # case lecal - genarate randomize
                if fuzz_session.priority==4 : 
                     record1 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), \
                        record_data=''.join( [chr(255) for i in xrange(0,random.randint(1,20))]))       
                     record2 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), \
                        record_data=''.join( [chr(255) for i in xrange(0,random.randint(1,10))]))                                                 
                fuzz_session.f_record1=record1
                records = [record1,record2,record3,record4];handle  = ReadFileRecordRequest(records)
                result  = struct.pack(">B",Read_File_record)+handle.encode()
                response=master1.execute_fpdu(slave,result); records = [fuzz_session.f_record1,record2,record3,record4]
                #fuzz_session.f_records=fuzzing records, not  original
                lgr.info('test records (first group-file,record,length)  %r response %r'  % (records,response,))
                if fuzz_session.flag_reguest==False :
                        break          
            fuzz_session.flag_reguest=True
            sleep(1.0)     

    """
    Write File Record Request FC : 21   
    Writes the contents of registers in Extended Memory file (6XXXXX) references.
    The function can write multiple groups of references. The groups can be separate
    (non–contiguous), but the references within each group must be sequential.
    file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
    The reference type: 1 byte (must be 0x06), The file number: 2 bytes, The starting record number within the file: 2 bytes
    The length of the record to be read: 2 bytes

    """
    def test_WriteFileRecordRequestEncode(self):
            
            for i in itertools.count():
                #case - legal genarate one vector input test
                record1 = FileRecord(file_number=0x01, record_number=0x02, record_data='\x00\x01\x02\x04')
                record2 = FileRecord(file_number=0x01, record_number=0x02, record_data='\x00\x0a\x0e\x04')
                record3 = FileRecord(file_number=0x02, record_number=0x03, record_data='\x00\x01\x02\x04')
                record4 = FileRecord(file_number=0x01, record_number=0x02, record_data='\x00\x01\x02\x04')
                #case lecal - genarate randomize
                if fuzz_session.priority==4 : 
                     record1 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), record_data=''.join( [chr(255) for i in xrange(0,random.randint(1,20))]))       
                     record2 = FileRecord(file_number=random.randint(1,10), record_number=random.randint(1,9999), record_data=''.join( [chr(255) for i in xrange(0,random.randint(1,10))]))       
                fuzz_session.f_record1=record1
                records = [record1,record2,record3,record4] ;handle  = WriteFileRecordRequest(records)
                result  = struct.pack(">B",Write_File_record)+handle.encode()
                response=master1.execute_fpdu(slave,result);records = [fuzz_session.f_record1,record2,record3,record4] 
                lgr.info('test records (first group-file,record,length) and response : %r, %r ' % (records, response))
                if fuzz_session.flag_reguest==False :
                    break
            fuzz_session.flag_reguest=True
            sleep(1.0)     
   
    """ Mask Write Register Request FC:22 , 
    param :address=0x0000, and_mask=0xffff, or_mask=0x0000
    This function code is used to modify the contents of a specified holding register 
    The normal response is an echo of the request. The response is returned after the register has been written
    """
    
    def test_MaskWriteRegisterRequestEncode(self):
        and_mask= 0x0000                                              
        or_mask= 0xFF                                                   
        vector_address =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/2 
        lgr.info('vector_address: %d , and_mask: %s or_mask: %s' % (vector_address,and_mask,or_mask))   
        fuzz_session.starting_address=vector_address 
        
        for i in itertools.count():
                #case lecal - genarate randomize
                if fuzz_session.priority==4 : 
                    vector_address =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG)
                    and_mask=random.randint(0,65535);or_mask=random.randint(0,65535);fuzz_session.starting_address=vector_address 
                                    
                handle  = MaskWriteRegisterRequest(vector_address, and_mask, or_mask)
                result  = struct.pack(">B",Mask_Write_Register)+handle.encode()
                response=master1.execute_fpdu(slave,result)
                lgr.info('answer >> testing_address: %d  response: %s '  % (fuzz_session.starting_address,(response,)))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True
        sleep(1.0)        
    
    """ Read/Write Multiple registers  FC: 23 (0x17)
    This function code performs a combination of one read operation and one write operation in a single MODBUS transaction
    Read Starting Address  2 Bytes  0x0000 to 0xFFFF
    Quantity to Read  2 Bytes  0x0001 to 0x007D /1-125
    Write Starting Address  2 Bytes  0x0000 to 0xFFFF
    Quantity  to Write   2 Bytes  0x0001 to 0X0079  /1-121
    Write Byte Count  1 Byte  2 x N*
    Write Registers Value  N*x 2 Bytes  
    *N  = Quantity to Write
    """
   
    def test_ReadWriteMultipleRegistersRequest(self):
        #case - legal genarate one vector input test
        address_read =(fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/2 
        address_write= (fuzz_session.MIN_HO_REG+fuzz_session.MAX_HO_REG)/3
        Mult_output_value=self.HO_REG_quantity*[self.output_value]            
        lgr.info('vector_address_read: %d , vector_address_write: %d,vector_quantity_of_x: %d, Mult_output_value: %d * [%d]' % (address_read,address_write,self.HO_REG_quantity ,self.HO_REG_quantity,self.output_value))                 
                             
        for i in itertools.count():
            #case - legal genarate randomize input test 
            if fuzz_session.priority==4 :  
                address_read =random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG);address_write= random.randint(fuzz_session.MIN_HO_REG, fuzz_session.MAX_HO_REG)             
                self.HO_REG_quantity= random.randint(1,125); self.Write_HO_REG_quantity=random.randint(1,121)
                Mult_output_value=self.Write_HO_REG_quantity*[self.output_value]

            fuzz_session.read_starting_address = address_read
            fuzz_session.write_starting_address= address_write
            
            arguments = {
                        'read_address':  fuzz_session.read_starting_address, 'read_count':self.HO_REG_quantity ,
                        'write_address': fuzz_session.write_starting_address, 'write_registers':Mult_output_value,    
                        } 
            handle  = ReadWriteMultipleRegistersRequest(**arguments)            
            result = struct.pack(">B",Read_Write_Multiple_Registers)+handle.encode()
            response=master1.execute_fpdu(slave,result)
                
            if fuzz_session.flag_reguest==False :
                break
        fuzz_session.flag_reguest=True
        sleep(1.0)

    """
    Read_Device_Information  FC : 43
    This function code allows reading the identification and additional
    information relative to the physical and functional description of a
    remote device, only.
    params  = {'read_code':[0x01,0x02], 'object_id':0x00, 'information':[] } 
    handle  = ReadDeviceInformationRequest(**params)'
    """
    def test_Read_Device_Information(self):            
        read_code = self.read_code 
        object_id = self.object_id
        lgr.info('read_code  0x%02X   object_id 0x%02X ' % (read_code,object_id,))   
        
        for i in itertools.count():
                #case - legal genarate randomize input test
                if fuzz_session.priority==4:read_code=random.randint(1,4);object_id=random.randint(0,255)                  
                
                handle  = ReadDeviceInformationRequest(read_code,object_id,information=[])
                result  = struct.pack(">B",Read_device_Identification)+handle.encode()        
                response=master1.execute_fpdu(slave,result)
                lgr.info('Answer >> read_code  0x%02X (%d) object_id 0x%02X (%d) response: %r'  % (fuzz_session.read_code,fuzz_session.read_code,fuzz_session.object_id,fuzz_session.object_id,response))
                if fuzz_session.flag_reguest==False :
                    break
        fuzz_session.flag_reguest=True
        sleep(1.0)            
    
#-----------------------------------------------------------------------------------------------------------------------#
# Read csv file for config  fuzzer/calc fuzz address list from class list_of_fuzz 
# np array for test address vs quantity in FC01, FC02, FC03 ..call class  pairsfind=pairs_address_qua()
#-----------------------------------------------------------------------------------------------------------------------#
class Rw_object_info(list_of_fuzz):
    

    def __init__(self):
        
        self.FCValues0 = []                                             
        self.FCValues1 = []
        self.IN_REG=[] 
        self.COILS=[]
        self.DIS_IN =[]
        self.HO_REG=[]

    def Read_CSvFile(self):
        lof=list_of_fuzz()
        pairsfind=pairs_address_qua()
        tip=test_illegal_PDU ()

        try :
                values = csv.reader(open('search.csv', 'rb'), delimiter='\t')
                #read 0 colume
                for row in values:
                      self.FCValues0.append(row[0])
                      self.FCValues1.append(row[1])
                      self.IN_REG.append(row[2])
                      self.COILS.append(row[3])
                      self.DIS_IN.append(row[4])
                      self.HO_REG.append(row[5])    
                # pop header
                self.FCValues0.pop(0)    
                self.FCValues1.pop(0)    
                self.IN_REG.pop(0)   
                self.COILS.pop(0)    
                self.DIS_IN.pop(0)   
                self.HO_REG.pop(0)
                #Merge list of FC  
                fuzz_session.FCmergedlist = self.FCValues0 + self.FCValues1                                
                #remove all empty strings and dumple item
                fuzz_session.FCmergedlist = filter(None, fuzz_session.FCmergedlist)
                fuzz_session.FCmergedlist = list(set(fuzz_session.FCmergedlist))                    
                
                self.IN_REG = filter(None,self.IN_REG);self.COILS = filter(None,self.COILS);\
                self.DIS_IN= filter(None,self.DIS_IN); self.HO_REG = filter(None,self.HO_REG)
                                                            
                #convert all strings in a list to ints and sort list
                fuzz_session.FCmergedlist = [int(i) for i in fuzz_session.FCmergedlist]
                self.IN_REG = [int(i) for i in self.IN_REG]
                self.COILS = [int(i) for i in self.COILS]
                self.DIS_IN = [int(i) for i in self.DIS_IN]
                self.HO_REG = [int(i) for i in self.HO_REG]  
               
                fuzz_session.FCmergedlist.sort()
                #for all list min/max address                        
                fuzz_session.MIN_COILS =min(self.COILS );fuzz_session.MAX_COILS =max(self.COILS )           
                fuzz_session.MIN_IN_REG=min(self.IN_REG);fuzz_session.MAX_IN_REG=max(self.IN_REG)           
                fuzz_session.MIN_DIS_IN=min(self.DIS_IN); fuzz_session.MAX_DIS_IN=max(self.DIS_IN)           
                fuzz_session.MIN_HO_REG=min(self.HO_REG);fuzz_session.MAX_HO_REG=max(self.HO_REG)
                                                
                #calculate fuzz  address for FC from class list_of_fuzz 
                # b is bountery of value
                fuzz_session.fuzz_addre_COILS=lof.list_of_address(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS)
                fuzz_session.fuzz_addre_COILS_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS,10)           
                fuzz_session.fuzz_addre_DIS_IN=lof.list_of_address(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN)
                fuzz_session.fuzz_addre_DIS_IN_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN,10)            
                fuzz_session.fuzz_addre_IN_REG=lof.list_of_address(fuzz_session.MIN_IN_REG,fuzz_session.MAX_IN_REG)
                fuzz_session.fuzz_addre_IN_REG_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_IN_REG,fuzz_session.MAX_IN_REG,10)
                fuzz_session.fuzz_addre_HO_REG=lof.list_of_address(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG)
                #
                fuzz_session.fuzz_addre_HO_REG_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG,10)
                
                #calculate fuzz quantity_and output_value  for FC from class list_of_fuzz   
                fuzz_session.quantity_of_x_list_coil=lof.list_of_quantity(1968,2000)
                fuzz_session.quantity_of_x_list_reg=lof.list_of_quantity(121,125)

                #from class list_of_fuzz for use cartesian product with a limited number of interests,
                #use fuzzing parameter PDU-use in test FC 16, F23, (quantity register 121,123, 125 +-10)
                #list_quantity_for_cart_prod(MIN,MAX,b), b +-
                fuzz_session.quantity_of_x_list_reg_cart=lof.list_quantity_for_cart_prod(121,125,2)
                fuzz_session.quantity_of_x_list_coil_cart=lof.list_quantity_for_cart_prod(1968,2000,2)
                
                #test for value field FC15-
                fuzz_session.output_value_test=lof.lib_exhaustive_256() ;  fuzz_session.values_test=lof.lib_word()
                fuzz_session.byte_count_test=lof.lib_byte_test(0,255,256);fuzz_session.lib_test_sub_diag=lof.lib_test_sub_diag()
                
                #from class list_of_fuzz for use fuzzing MBAP
                fuzz_session.lib_of_MBAP_transid=lof.lib_of_MBAP_transid(0,65535);fuzz_session.lib_of_MBAP_protocol=lof.lib_of_MBAP_protocol(32768,65535)
                fuzz_session.lib_of_MBAP_Unit_id=lof.lib_byte_test(0,255,256);fuzz_session.lib_of_MBAP_length=lof.lib_of_MBAP_length() 
                           
                #len of list address 
                fuzz_session.len_of_COILS=len(fuzz_session.fuzz_addre_COILS)
                fuzz_session.len_of_DIS_IN=len(fuzz_session.fuzz_addre_DIS_IN)
                fuzz_session.len_of_HO_REG=len(fuzz_session.fuzz_addre_IN_REG)
                fuzz_session.len_of_IN_REG=len(fuzz_session.fuzz_addre_HO_REG)
                #len of library for test field quantity and output_value
                fuzz_session.len_quantity_of_COILS=len(fuzz_session.quantity_of_x_list_coil)
                fuzz_session.len_quantity_of_REG=len(fuzz_session.quantity_of_x_list_reg)
                #last element of a list use in test PDU field 1-way, 2-way for flag with end test
                fuzz_session.l_fuzz_addre_COILS=fuzz_session.fuzz_addre_COILS[-1]
                fuzz_session.l_fuzz_addre_DIS_IN=fuzz_session.fuzz_addre_DIS_IN[-1]
                fuzz_session.l_fuzz_addre_HO_REG=fuzz_session.fuzz_addre_HO_REG[-1]
                fuzz_session.l_fuzz_addre_IN_REG=fuzz_session.fuzz_addre_IN_REG[-1]
                fuzz_session.l_quantity_of_COILS=fuzz_session.quantity_of_x_list_coil[-1]
                fuzz_session.l_quantity_of_REG=fuzz_session.quantity_of_x_list_reg[-1]
                fuzz_session.l_output_value=fuzz_session.values_test[-1]
                fuzz_session.l_output_value_test=fuzz_session.output_value_test[-1]
                fuzz_session.l_byte_count=fuzz_session.byte_count_test[-1]
                fuzz_session.l_item_test_sub_diag=fuzz_session.lib_test_sub_diag[-1]

                #last element of a list, use in test MBAP, case not duplicates elements/ is short list
                fuzz_session.l_lib_of_MBAP_transid=fuzz_session.lib_of_MBAP_transid[-1]
                fuzz_session.l_lib_of_MBAP_protocol=fuzz_session.lib_of_MBAP_protocol[-1]
                fuzz_session.l_lib_of_MBAP_Unit_id=fuzz_session.lib_of_MBAP_Unit_id[-1]
                fuzz_session.l_lib_MBAP_length=fuzz_session.lib_of_MBAP_length[-1]

                #FC 20, 21, calculate fuzz byte count, address and FILES for FC from class list_of_fuzz 
                #one_byte_test=29 value, apply in test pairwise par((0,*,255),(0,*,65535))
                #two_byte_test= value,record_length, FC 21, 2X122 MAX VALID packet
                fuzz_session.count_byte_test=lof.lib_byte_test(7,245,256); fuzz_session.ref_byte_test=lof.lib_byte_test(0,6,256)
                fuzz_session.fuzz_files_rum=lof.lib_byte_test(0,10,65535);fuzz_session.fuzz_files_rec=lof.lib_byte_test(0,9999,65535)       
                fuzz_session.record_length=lof.lib_byte_test(0,122,65535)
               
                #last element of a list use FC 20,21
                fuzz_session.l_lib_of_files_rum=fuzz_session.fuzz_files_rum[-1]
                fuzz_session.l_lib_of_files_rec=fuzz_session.fuzz_files_rec[-1]
                fuzz_session.l_count_byte_test=fuzz_session.count_byte_test[-1]
                fuzz_session.l_ref_byte_test=fuzz_session.ref_byte_test[-1]
                fuzz_session.l_record_length=fuzz_session.record_length[-1]
                fuzz_session.l_fuzz_files_rec=fuzz_session.fuzz_files_rec[-1]

                #np array for test address vs quantity in FC01, FC02, FC03 ..
                #call class  pairsfind=pairs_address_qua(), param  max and min address
                #READ_COILS = 1,READ_DISCRETE_INPUTS = 2,READ_HOLDING_REGISTERS = 3,READ_INPUT_REGISTERS = 4
             
                pairwice_READ_COILS=pairsfind.pair(READ_COILS,fuzz_session.fuzz_addre_COILS_cart,fuzz_session.quantity_of_x_list_coil_cart,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS )
                pairwice_READ_DISCRETE_INPUTS=pairsfind.pair(READ_DISCRETE_INPUTS,fuzz_session.fuzz_addre_IN_REG_cart,fuzz_session.quantity_of_x_list_coil_cart,fuzz_session.MAX_DIS_IN,fuzz_session.MIN_DIS_IN )
                pairwice_READ_HOLDING_REGISTERS=pairsfind.pair(READ_HOLDING_REGISTERS,fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart,fuzz_session.MAX_HO_REG,fuzz_session.MIN_HO_REG)
                pairwice_READ_INPUT_REGISTERS=pairsfind.pair(READ_INPUT_REGISTERS,fuzz_session.fuzz_addre_IN_REG_cart,fuzz_session.quantity_of_x_list_reg_cart,fuzz_session.MAX_IN_REG,fuzz_session.MIN_IN_REG )
                        
                lgr.info('--------------------------    Configuration Read from CSV  -------------------------------------------\n')
                lgr.info('FCmergedlist : %s' %fuzz_session.FCmergedlist)            
                lgr.info('COILS_list : %s' %self.COILS);lgr.info('DIS_IN_list : %s' %self.DIS_IN)     
                lgr.info('HO_REG: %s' % self.HO_REG) ; lgr.info('IN_REG_list : %s' %self.IN_REG)         
                self.print_info_test()

        except IOError:
                lgr.error('No such file or directory: search.csv')
                sys.exit(1)

    def print_info_test(self):
        tip=test_illegal_PDU ()
        lof=list_of_fuzz()        

        lgr.info('---------------------------- Set Configuration --------------------------------------------------------\n')
        lgr.info('start_address READ_COILS : %d' %fuzz_session.MIN_COILS )
        lgr.info('last_address READ_COILS : %d' %fuzz_session.MAX_COILS )
        lgr.info('start_address READ_DISCRETE_INPUTS: %d' %fuzz_session.MIN_DIS_IN)
        lgr.info('last_address READ_DISCRETE_INPUTS: %d' %fuzz_session.MAX_DIS_IN)
        lgr.info('start_address READ_HOLDING_REGISTERS: %d' %fuzz_session.MIN_HO_REG)
        lgr.info('last_address READ_HOLDING_REGISTERS: %d' %fuzz_session.MAX_HO_REG)
        lgr.info('start_address READ_INPUT_REGISTERS: %d' %fuzz_session.MIN_IN_REG)
        lgr.info('last_address READ_INPUT_REGISTERS: %d' %fuzz_session.MAX_IN_REG)
        lgr.info('\n---------------------------- Set Configuration for function 20,21,22 -----------------------------------')
        lgr.info('total of test Byte count : %d' %len(fuzz_session.count_byte_test))
        lgr.info('Value of test Byte count : %r' %fuzz_session.count_byte_test)
        lgr.info('total of test Reference Type : %d' %len(fuzz_session.ref_byte_test))
        lgr.info('Value of test Reference Type : %r' %fuzz_session.ref_byte_test)
        lgr.info('start_address_records : %d' %start_address_reco)
        lgr.info('Value of test file number : %r' %fuzz_session.fuzz_files_rum)
        lgr.info('total of test file number : %d' %len(fuzz_session.fuzz_files_rum))
        lgr.info('Value of test files records: %r' %fuzz_session.fuzz_files_rec)
        lgr.info('total of files records: : %d' %len(fuzz_session.fuzz_files_rec))
        lgr.info('Value of test records length: %r' %fuzz_session.record_length)
        lgr.info('total of records length: : %d' %len(fuzz_session.record_length))

        lgr.info('\n---------------------------- Set Configuration for MBAP ------------------------------------------------')
        lgr.info('Value of test  MBAP transaction: %r' %fuzz_session.lib_of_MBAP_transid)
        lgr.info('total of test  MBAP transaction: %d' %len(fuzz_session.lib_of_MBAP_transid))
        lgr.info('Value of test MBAP  protocol: %r' %fuzz_session.lib_of_MBAP_protocol)
        lgr.info('total of test  MBAP protocol: %d' %len(fuzz_session.lib_of_MBAP_protocol))
        lgr.info('Value  of test MBAP Unit id: %r' %(fuzz_session.lib_of_MBAP_Unit_id))
        lgr.info('total of test  MBAP Unit id: %d' %len(fuzz_session.lib_of_MBAP_Unit_id))
        lgr.info('Value of test MBAP  length: %r' %fuzz_session.lib_of_MBAP_length)
        lgr.info('total of test  MBAP length: %d' %len(fuzz_session.lib_of_MBAP_length))
        
        lgr.info('\n---------------------------- Set Configuration quantity_of_x_list, address for single test fields and 2-way--------------------')
        lgr.info('address COILS_list : %s' %fuzz_session.fuzz_addre_COILS); lgr.info('num COILS list : %d' %len(fuzz_session.fuzz_addre_COILS))
        lgr.info('address COILS_list_cart : %s' %fuzz_session.fuzz_addre_COILS_cart);lgr.info('num COILS list_cart : %d' %len(fuzz_session.fuzz_addre_COILS_cart)) 
        lgr.info('')
        lgr.info('address HO_REG list : %s' % fuzz_session.fuzz_addre_HO_REG)
        lgr.info('num HO_REG list : %d' %len(fuzz_session.fuzz_addre_HO_REG))
        lgr.info('address HO_REG_list_cart : %s' %fuzz_session.fuzz_addre_HO_REG_cart)
        lgr.info('num HO_REG  list_cart : %d' %len(fuzz_session.fuzz_addre_HO_REG_cart))
        lgr.info('')
        lgr.info('address DISCRETE_INPUTS list : %s' % fuzz_session.fuzz_addre_DIS_IN)
        lgr.info('')
        lgr.info('num DISCRETE_INPUTS  list : %d' %len(fuzz_session.fuzz_addre_DIS_IN))
        lgr.info('address DISCRETE_INPUTS_list_cart : %s' %fuzz_session.fuzz_addre_DIS_IN_cart)
        lgr.info('num DISCRETE_INPUTS  list_cart : %d' %len(fuzz_session.fuzz_addre_DIS_IN_cart))
        lgr.info('')
        lgr.info('address READ_INPUT_REGISTERS list : %s' % fuzz_session.fuzz_addre_IN_REG)
        lgr.info('num READ_INPUT_REGISTERS list : %d' %len(fuzz_session.fuzz_addre_IN_REG))
        lgr.info('address READ_INPUT_REGISTERS_list_cart : %s' %fuzz_session.fuzz_addre_IN_REG_cart)
        lgr.info('num READ_INPUT_REGISTERS list_cart : %d' %len(fuzz_session.fuzz_addre_IN_REG_cart))
        lgr.info('')           
        lgr.info('quantity_of_x_list for coils: %s' %fuzz_session.quantity_of_x_list_coil)
        lgr.info('num quantity_of_x_list for coils: %d' %len(fuzz_session.quantity_of_x_list_coil))
        lgr.info('quantity_of_x_list for coils _cart: %s' %fuzz_session.quantity_of_x_list_coil_cart)
        lgr.info('num quantity_of_x_list for coils_cart_prod: %d' %len(fuzz_session.quantity_of_x_list_coil_cart))
        lgr.info('')
        lgr.info('quantity_of_x_list for register: %s' %fuzz_session.quantity_of_x_list_reg)
        lgr.info('')
        lgr.info('num quantity_of_x_list for register: %d' %len(fuzz_session.quantity_of_x_list_reg))
        lgr.info('quantity_of_x_list for register_cart: %s' %fuzz_session.quantity_of_x_list_reg_cart)
        lgr.info('num quantity_of_x_list for register_cart_prod: %d' %len(fuzz_session.quantity_of_x_list_reg_cart))
        lgr.info('num  for cartesian VALUE TEST: %r' %lof.lib_word_cart())
        lgr.info('num  for cartesian VALUE TEST: %d' %len(lof.lib_word_cart()))
        lgr.info('') 
        lgr.info("PAIRWISE test Initializes from CSV for address vs quantity ")
        lgr.info('Test case Initializing READ_COILS : %d '% np.size(pairwice_READ_COILS, 0))
        lgr.info('Test case Initializing READ_DISCRETE_INPUTS : %d '% np.size(pairwice_READ_DISCRETE_INPUTS, 0))
        lgr.info('Test case Initializing READ_HOLDING_REGISTERS : %d '% np.size(pairwice_READ_HOLDING_REGISTERS, 0))
        lgr.info('Test case Initializing READ_INPUT_REGISTERS : %d '% np.size(pairwice_READ_INPUT_REGISTERS, 0))

        lgr.info('---------------------------------------------------------------------------------------------------------\n')
        lgr.info('test bit_field  library records (word): %r'%fuzz_session.values_test)
        lgr.info('num bit_field  library records (word) : %s' %len(fuzz_session.values_test))
        lgr.info('library for test byte count field : %r'%fuzz_session.byte_count_test)
        lgr.info('num library for test byte count field :%d' %len(fuzz_session.byte_count_test))
        lgr.info('library for test Sub-function codes : %r'%fuzz_session.lib_test_sub_diag)
        lgr.info('num library for test Sub-function codes: %d' %len(fuzz_session.lib_test_sub_diag))
        tip=test_illegal_PDU ()

        lgr.info('')
        lgr.info('Set Configuration for fuzzing not specification message len and Dumplicate (ADU address x quantity_of')
        lgr.info('---------------------------------------------------------------------------------------------------------\n')
        lgr.info('address COILS_list : %s' %tip.A_CO)
        lgr.info('num COILS list : %d' %len(tip.A_CO))            
        lgr.info('')
        lgr.info('address HO_REG list : %s' % tip.A_HR)
        lgr.info('num HO_REG list : %d' %len(tip.A_HR))
        lgr.info('')
        lgr.info('address DISCRETE_INPUTS list : %s' % tip.A_DI)
        lgr.info('')
        lgr.info('num DISCRETE_INPUTS  list : %d' %len(tip.A_DI))
        lgr.info('')
        lgr.info('address READ_INPUT_REGISTERS list : %s' % tip.A_IR)
        lgr.info('num READ_INPUT_REGISTERS list : %d' %len(tip.A_IR))
        lgr.info('')
        lgr.info('quantity_of_x_list for coils: %s' %tip.QC)
        lgr.info('')
        lgr.info('num quantity_of_x_list for coils: %s' %len(tip.QC))
        lgr.info('')
        lgr.info('quantity_of_x_list for register: %s' %tip.QH)
        lgr.info('')
        lgr.info('num quantity_of_x_list for register: %s' %len(tip.QH))
        lgr.info('')
        lgr.info('list of dumplicate ADU test: %s' %tip.list_of_dumpl_number())
        lgr.info('')
        lgr.info('num quantity list dumplicate ADU: %d' %len(tip.list_of_dumpl_number()))
        lgr.info('list of lengths with random or smart characters : %s' % fuzz_session.illegal_pdu_len)
        lgr.info('')
        lgr.info('Number test case per FC of length illegal message PDU: : %d' %len(fuzz_session.illegal_pdu_len))
        lgr.info('---------------------------------------------------------------------------------------------------------\n')
        lgr.info('Number interesting Byte : %d' % len(fuzz_session.bytehex))
        lgr.info('list of interesting Byte: %s ' % fuzz_session.bytehex)
                
def do_work( forever=True):
    """
    The main fuzzer function,start with a socket at 1-second timeout,set parametre host 

    """
    global num_of_request,host
    
    while True:
        MAXIMUM_NUMBER_OF_ATTEMPTS=3
        # 
        lgr.info ("Creating the socket")
        master1.__init__(host=host, port=502, timeout_in_sec=1.0)
           
        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):             
            try:           
                master1.open_b()
                lgr.info('Socket connect worked!'); start_fuzzer()                 
                                   
            # except EnvironmentError as exc:
            except socket.error as socketerror:
                lgr.error("Socket Error: %s ", (socketerror))
                lgr.error('Socket connect failed! Loop up and try socket again')               
                time.sleep(1.0); continue                      
        else :
            lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)                       
            lgr.info("Fuzzer terminate !!.")
            master1.close();sys.exit(1)
            
def start_fuzzer():
    """ 
    Initializing Fuzzer started, start time for duration time
    Initializing fuzz_operation dictionary
    Read csv file for config  fuzzer/calc fuzz address list from class list_of_fuzz 
    p=dict_fuzz_object()
    p.int_fuzz_operation()
    rw_obj=Rw_object_info(),  

    """
    global running,fuzz_mode,search_mode,start_time,end_time,num_of_request,pcap_mode
    start_time = datetime.now()
    p=dict_fuzz_object();p.int_fuzz_operation()
    rw_obj=Rw_object_info()                           
    lgr.info('Initializing fuzz log reader and fuzz_operation dictionary');lgr.info('Fuzzer started ')
    
    # phese I Search FC and address
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode==False:
            lgr.info('Running  in Search_mode True!')         
            b_box=black_box()                      # object for scan  function support ans map address
            b_box.con_SUT()                        # run test black box                                  
            info(start_time,num_of_request)        # info time and request 
            sys.exit(1)                                        
            
    elif  fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode== True :
            lgr.info('Running  in Search_mode True and pcap_mode!')
            b_box=black_box()                      # object for scan  function support ans map address            
            b_box.con_SUT_pcap()                   # read pcap file and add info in csv file          
            info(start_time,num_of_request)
            sys.exit(1)   

    elif  fuzz_session.search_mode==False and fuzz_session.fuzz_mode==True and fuzz_session.pcap_mode== False:      
            """fuzzer operation querie, search_mode False from command line param"""

            lgr.info('Running in fuzzing_mode')
            rw_obj.Read_CSvFile()                 # read file csv and append list for configuration          
            s=SetupAndTeardown()                  # object for fuzzer            
            s.con() 
            info(start_time,num_of_request)       # info time and request             
            sys.exit(1)                                       
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==False:
            """run test black box """ 
            
            lgr.info('Running in search mode and fuzzing mode')
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False
            b_box=black_box()                     # object for scan  function support ans map address
            b_box.con_SUT()                       # run test black box 
            
            """run fuzzer mode and read csvFile"""
            fuzz_session.search_mode=False
            fuzz_session.fuzz_mode=True            
            rw_obj.Read_CSvFile()                 # read file csv and append list for configuration
            s=SetupAndTeardown()                  # object for fuzzer            
            s.con()                               # fuzzer querie 
            info(start_time,num_of_request)       # info time and request 
            sys.exit(1) 
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==True :
            """run read from pcap file """ 
            
            lgr.info('Running in search mode and fuzzing mode and pcap file')                          
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False
            b_box=black_box()                      # object for scan  function support ans map address            
            b_box.con_SUT_pcap()                   # read pcap file and add info in csv file 
                                      
            """run fuzzer mode and read csvFile"""
            fuzz_session.fuzz_mode=True            
            fuzz_session.search_mode=False
            fuzz_session.pcap_mode=False
            rw_obj.Read_CSvFile()                 # read file csv and append list for configuration
            s=SetupAndTeardown()                  # object for fuzzer           
            s.con()                               # fuzzer querie 
            info(start_time,num_of_request)       # info time and request 
            sys.exit(1) 

    else :
            lgr.info('search_mode none/fuzz_mode None!')
        
def print_usage():
      print sys.argv[0], '-i <host>  -s <search_mode> -z <fuzz_mode> -f <csvFile=search.csv> -p <pcap_file=packets.pcap> -t <suite test> -r <normal_request>'   

#----------------------------------------------------------------------------------------------------------#
# The main function, reads the fuzzer arguments and starts the fuzzer
# create a directory if it does not exist, log_dir=./log 
# o == option
# a == argument passed to the o
# test_suites_list = [('test_MBAP', 1.0), ('test_message_PDU', 2.0), ('test_field_PDU', 3.0),('Not_fuzz',4.0)]
# e.g python2 mtf.py -i 127.0.0.1  -z -f -t 1 for MBAP test
#------------------------------------------------------------------------------------------------------------#
def main():
   global host, log_dir,log_file,fuzz_mode,search_mode,csvFile,filename,pcap_file,pcap_mode
   
   try : 
       opts, args = getopt.getopt(sys.argv[1:], 'i:se:ze:pe:fe:t:r:')
   except getopt.GetoptError as err:
       print str(err);print_usage(); sys.exit(0)

   for o, a in opts:
      print o, a
      
      if o == '-i':
         host = a
      
      elif o == '-s':
         fuzz_session.search_mode = True

      elif o == '-p':
         #host = a 
         pcap_file="packets.pcap"            
         fuzz_session.pcap_mode = True
                                                           
      elif o == '-f':
         csvFile="search.csv"                
                    
      elif o == '-z':
         fuzz_session.fuzz_mode = True

      #define suite test each FC, Defaults suite test 0 / test all suite??
      elif o == '-t':         
         fuzz_session.priority = int(a)

      #define, send request 1000 defaults
      elif o == '-r':         
          fuzz_session.normal_request = int(a)
      
      else: 
         assert False, "unhandled option"   
                      
   lgr.info('SUT Unit IP address : ' + host )                          
   lgr.info('path log file info: '+ log_dir + filename1)
   lgr.info('path log file error: '+ log_dir + filename2 )
   lgr.info('csvFile : ' + "./" + csvFile)                         
   lgr.info('pcap_file: ' + "./" + pcap_file) 
   lgr.info('Choice suite test for each FC: %d' %fuzz_session.priority)
   lgr.info('Case 4 normal request for each FC: %d',fuzz_session.normal_request)    
   
   if (pcap_file != "" and csvFile != ""):
      start_fuzzer() 

   elif(host is None  or csvFile == "" or log_dir=="" or  fuzz_session.priority >4):
      print_usage()
      sys.exit(0)
   
   elif (fuzz_session.search_mode==False and fuzz_session.fuzz_mode==False):
      print_usage() 
      sys.exit(0)        


   do_work(True)
   
if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    Cleaning_up()                                             # Cleaning up  log files in dir ./ 
    master1 = modbus_tcp_b.TcpMaster_b()           
    log_info(lgr,logger)

    main() 
    
    
    
    
    
