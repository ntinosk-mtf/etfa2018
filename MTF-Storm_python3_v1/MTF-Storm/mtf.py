#!//usr//bin//env python
# -*- coding: utf_8 -*-
"""
 This is distributed under GNU LGPL license, 
 Source code for Modbus//TCP fuzzer used for the ETFA 2015//2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr
 Use Modbus TestKit: Implementation of Modbus protocol in python
 The modbus_tk simulator is a console application which is running a server with TCP  

"""

import getopt,traceback,math,sys
import csv,operator,os,signal
import functools
import logging.handlers as handlers
import decimal
import itertools
import numpy as np #Numpy provides a large set of numeric datatypes that you can use to construct arrays.

#Use Modbus TestKit
import modbus_tk
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
import modbus_tk.hooks as hooks
import fuzz_session

from itertools import zip_longest
from itertools import count
from time import * 
from datetime import datetime
from random import *
from struct import *
from itertools import chain
from math import ceil
from hashlib import sha256
from collections import OrderedDict
from scapy.all import *   #Use scapy TestKit
import scapy.layers.l2
import scapy.layers.inet
from scapy.error import Scapy_Exception
from scapy.contrib.modbus import *                 
from scapy.utils import warning,get_temp_file,PcapReader,wrpcap 
from utils_b import *
from allpairspy import allpairs #Use allpairspy, https://github.com/thombashi/allpairspy 
from logging.handlers import RotatingFileHandler #The RotatingFileHandler 
from coloredlogs import ColoredFormatter #The RotatingFileHandler and the coloredlogs package enables colored terminal output for Python’s logging module.
from add_method  import * #define  function, exception, add method e.a
from defines import *
from ifuzzer import change_test_format,Read_CSv_FC
from raise_except import (CsvError,TestfieldError,ModbusError)

import libraries #library from sulley, dict_operation,library for static fuzz VALUE  e.g ,library for write results to file *.csv for test single field,write results  Coverage 
import basetest 
import product
from  product.testQueries import TestQueries as TestQueries
from  product.testQueriesSerialFC import TestQueriesSerialFC as TestQueriesSerialFC
from product.message import *  
from product.serial_message import *
from product.diag import *


#--------------------------------------------------------------------------------------------------------------------#
#Modbus tcp //basic :
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
#   23 (0x17) Read//Write Multiple Registers   
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
#   43 ( 0x2B) sub code 13//14 Encapsulated Interface Transpor   
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
#----READ_COILS// READ_DISCRETE_INPUTS

#Function code      1 Byte    0x01//0x02
#Starting Address   2 Bytes   0x0000 to 0xFFFF
#Quantity of coils  2 Bytes   1 to 2000 (0x7D0)

#-----READ_HOLDING_REGISTERS//READ_INPUT_REGISTERS 
#Function code          1   Byte    0x03//0x04
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

#------------------------------------------------------------------------------------------------------
# This class about global variable mode search and fuzzing not use  //Use module fuzz_session.py, defines.py
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
# filtered_pcap    --trace pcap file request//response modbus
# mod_file_response -trace pcap file //response modbus
# mod_file_request  -trace pcap file request//modbus

# log to the console
#console_handler = logging.StreamHandler()
#level = logging.INFO
#console_handler.setLevel(level)
#logger.addHandler(console_handler)
#create console handler and set level to debug
#ch = logging.StreamHandler()
#ch.setLevel(logging.INFO)

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
    If rotation//rollover is wanted, it doesn't make sense to use another
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

# create logger- -disable log file as >>lgr.disabled = True 
logger = modbus_tk.utils.create_logger("console")
lgr=logging.getLogger('') #lgr.disabled = True  


def log_info(lgr,logger,minLevel=logging.INFO,dir=log_dir) :
    ''' 
    add a rotating handler and compression
    add a file handler//two separation file, 100mb // change
    add filter exeption logging.INFO from  debug log 
    You can specify particular values of maxBytes and backupCount to allow the file to rollover at a predetermined size.
    If backupCount is > 0, when rollover is done, no more than backupCount files are kept - the oldest ones are deleted.
    set up logging to file
    DEBUG
    INFO
    WARNING
    ERROR
    FATAL//CRITICAL//EXCEPTION 
    create a directory if it does not exist log_dir=.//log
    Set up logging to the console-it prints to standard output
    The coloredlogs package enables colored terminal output for Python’s logging module.  
    '''          
   
    global filename1,filename2,log_dir
    # Define the default logging message formats.
    file_msg_format = '%(asctime)s %(levelname)-8s: %(message)s'
    console_msg_format = '%(levelname)s: %(message)s'
    
    # Validate the given directory.--NEW
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


def info(start_time,num_of_request):
    """
    This function print info time duration and total request
    """
    
    end_time = datetime.now()
    lgr.info('Duration: {}'.format(end_time - start_time)) 
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==True :
       lgr.info('Total request of reconnaissance: %d', fuzz_session.num_of_reco)
       lgr.info('Total request: %d', fuzz_session.num_of_request)     
    elif fuzz_session.fuzz_mode==True :
        lgr.info('Total request: %d', fuzz_session.num_of_request)     

def signal_handler(signal, frame):
   """
   This function cleans temporary files and stop the fuzzer 
   upon Ctrl+c event

   """
   #lgr.info('Stopping  Ctrl+c ')
   lgr.info("You hit control-c")
   info(start_time,num_of_request)     # info time and request
   fuzz_session.master1.close();sys.exit(0)

def Cleaning_up():

   """
   This function cleans temporary log files, csvtestformat,csvtestPDU,tmpAllpair
   /csvtest** save csv file for FC 
   log_dir = "./log/" and fil*.pcap files
   """   
   
   lgr.info('Cleaning up  log files and ./tmpCSVtest')
   os.system('sudo rm -rf ' + log_dir + '*.log.*')
   os.system('sudo rm -rf ' + log_dir + '*.log')
   os.system('sudo rm -rf ' + './csvtest*' + '/*.csv')
   os.system('sudo rm -rf ' + './tmpAllpair*' + '/*.csv')
   os.system('sudo rm -rf ' + './fil*.pcap')

class SetupAndTeardown(object):
    lof=libraries.list_of_fuzz()    
    fuzz_session.illegal_pdu_len=lof.illegal_len_list()

    def __init__(self,host="localhost", port=502, timeout_in_sec=1.0):

        self._timeout = timeout_in_sec
        self._host = host
        self._port = port
        self._is_opened = False
        
        
    def setUp(self):            
        self.fuzz_session.master1 = modbus_tcp_b.TcpMaster_b()
        self.fuzz_session.master1.set_timeout(1.0)
        self.fuzz_session.master1.open()
        time.sleep(1.0)
    
    def tearDown(self):
        self.fuzz_session.master1.close()

    #demo test 
    def recon_do_work(self,ever=True) :
        global host               
        
        MAXIMUM_NUMBER_OF_ATTEMPTS=3                        
        lgr.info("Creating the socket reconnect")
        fuzz_session.master1.__init__(host=host, port=502, timeout_in_sec=1.0)

        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):            
            try:           
                fuzz_session.master1.open_b()
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
                fuzz_session.master1.close();sys.exit(1)
                

    def con (self):
                global forever          
                t=TestQueries();tsf=TestQueriesSerialFC()
                
                while True:                                                                          

                    try:     
                       
                        if READ_COILS in fuzz_session.FCmergedlist:
                            
                            """Check that read coil queries are handled correctly """
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 01: READ_COILS .... ')
                            t.test_readcoil()   
                            lgr.info('\t Finally! Fuzz testing  READ_COILS  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(READ_COILS)                           
                            
                        elif READ_DISCRETE_INPUTS in fuzz_session.FCmergedlist :       

                            """Check that ReadDiscreteInputs queries are handled correctly"""                            
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 02: READ_DISCRETE_INPUTS.... ') 
                            t.test_ReadDiscreteInputs()
                            lgr.info('\t Finally!  Fuzz testing  READ_DISCRETE_INPUTS!!.' )
                            fuzz_session.FCmergedlist.remove(READ_DISCRETE_INPUTS)
                           
                        elif READ_HOLDING_REGISTERS in fuzz_session.FCmergedlist : 
                           
                            """Check that  HOLDING_REGISTERS queries are handled correctly"""                           
                            lgr.info('')
                            lgr.info(' \t Fuzzing FC 03: READ_HOLDING_REGISTERS .... ')
                            t.test_readhr()
                            lgr.info(' \t Finally!  Fuzz testing  READ_HOLDING_REGISTERS DONE !!.' )
                            fuzz_session.FCmergedlist.remove(READ_HOLDING_REGISTERS)
 

                        elif READ_INPUT_REGISTERS  in fuzz_session.FCmergedlist :
                                                   
                            """Check that  queries READ_INPUT_REGISTERS are handled correctly"""
                            lgr.info('')
                            lgr.info(' \t Fuzzing FC 04: READ_INPUT_REGISTERS... ') 
                            t.test_ReadAnalogInputs()
                            lgr.info('\t Finally! Fuzz testing  READ_INPUT_REGISTERS  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(READ_INPUT_REGISTERS)

                              
                        elif WRITE_SINGLE_COIL in fuzz_session.FCmergedlist :
                           
                            """Check that write coil queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 05: WRITE_SINGLE_COIL .... ')
                            t.test_writecoil()
                            lgr.info('\t Finally!  Fuzz testing WRITE_SINGLE_COIL  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_SINGLE_COIL)

                        
                        elif WRITE_SINGLE_REGISTER in fuzz_session.FCmergedlist :

                            """Check that write HOLDING_REGISTERS queries are handled correctly"""                          
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 06: WRITE_SINGLE_REGISTER.... ')
                            t.test_writesingleHr()
                            lgr.info('\t Finally! Fuzz testing  WRITE_SINGLE_REGISTER  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_SINGLE_REGISTER )


                        elif WRITE_MULTIPLE_COILS in fuzz_session.FCmergedlist :
                     
                            """Check that write WriteMultipleCoils queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 15: WRITE_MULTIPLE_COILS .... ')
                            t.test_WriteMultipleCoils()
                            lgr.info('\t Finally! Fuzz testing  WRITE_MULTIPLE_COILS DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_MULTIPLE_COILS)
                            
                        
                        elif WRITE_MULTIPLE_REGISTERS in fuzz_session.FCmergedlist :

                            """Check that write WriteMultipleHr  queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 16: WRITE_MULTIPLE_REGISTERS .... ')
                            t.test_WriteMultipleHr()
                            lgr.info('\t Finally!  Fuzz testing WRITE_MULTIPLE_REGISTERS  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(WRITE_MULTIPLE_REGISTERS)
                                                  
                            """ the request is new function from pymodbus 1.3.2"""                  

                        elif Read_File_record in fuzz_session.FCmergedlist :

                            """Check that Read_File_record queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 20: Read_File_record .... ')
                            t.test_ReadFileRecordRequestEncode()
                            lgr.info('\t Finally!  Fuzz testing  Read_File_record  DONE !!.' )
                            fuzz_session.FCmergedlist.remove(Read_File_record)
                            

                        elif Write_File_record in fuzz_session.FCmergedlist :      

                            """Check that Write_File_record queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 21: Write_File_record .... ')
                            t.test_WriteFileRecordRequestEncode()
                            lgr.info('\t Finally!  Fuzz testing  Write_File_record   DONE !!.' )
                            fuzz_session.FCmergedlist.remove(Write_File_record )
                            
                              
                        elif Mask_Write_Register in fuzz_session.FCmergedlist :      

                            """Check that Mask_Write_Register queries are handled correctly"""
                            lgr.info(''); lgr.info('\t Fuzzing FC 22: Mask_Write_Register .... ')
                            t.test_MaskWriteRegisterRequestEncode()
                            lgr.info('\t Finally! Fuzz testing  Mask_Write_Register DONE !!.' )
                            fuzz_session.FCmergedlist.remove(Mask_Write_Register)
                            
                              
                        elif Read_Write_Multiple_Registers in fuzz_session.FCmergedlist :      

                            """Check that Read_Write_Multiple_Registers are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 23: Read_Write_Multiple_Registers .... ')
                            t.test_ReadWriteMultipleRegistersRequest()
                            lgr.info('\t Finally! Fuzz testing  Read_Write_Multiple_Registers !!.' )
                            fuzz_session.FCmergedlist.remove(Read_Write_Multiple_Registers)
                            
                  
                        elif Read_FIFO_queue in fuzz_session.FCmergedlist :  

                            """Check that ReadFifoQueueRequestEncode queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 24: Read_FIFO_queue  .... ')
                            t.test_ReadFifoQueueRequestEncode()
                            lgr.info('\t Finally! Fuzz testing  Read_FIFO_queue  DONE !!.')
                            fuzz_session.FCmergedlist.remove(Read_FIFO_queue)

                        elif Read_device_Identification in fuzz_session.FCmergedlist :  

                            """Check ReadDeviceInformationRequest queries are handled correctly"""
                            lgr.info('')
                            lgr.info('\t Fuzzing FC 43: Read Device Identification interface  .... ')
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
                            #Testing diagnostic request messages for all sub_function_code and data field (0,65535)
                            #in case test PDU fields 2-way
                            if fuzz_session.way==2 and fuzz_session.priority==3 : #fuzz_session.priority==3/test_field_PDU/ 2-way
                                fuzz_session.flag_test_FC08_pair==True
                                tsf.test_DiagnosticRequests_data_field()
                                fuzz_session.flag_test_FC08_pair=False     
                            elif fuzz_session.way==1 and fuzz_session.priority in (1,3): tsf.test_DiagnosticRequests() #fuzz_session.way=1
                            # fo=0,1,2 , (defaults) fo=0 all test
                            else : fuzz_session.flag_test_FC08_pair==True;tsf.test_DiagnosticRequests() #fuzz_session.way= 0,or fuzz_session.  
                            lgr.info('\t Finally! Fuzz testing  Diagnostics  !.')                            
                            fuzz_session.FCmergedlist.remove(Diagnostics)       
                        
                        else :                           
                            lgr.info('Error/Empty/not fuzzing FClist : %s' %fuzz_session.FCmergedlist)                                                                             
                            break

                    except ModbusError as ex:                      
                           lgr.error("%s- Code=%d" % (ex, ex.get_exception_code()))
                           pass                                                                                                                                                                                                     
                           
                    #e.g connection refuse,broken pipe,reset by peer -loop and try recv() again new connection , 
                    #errno.EPIPE errno.ECONNRESET                                                                                                                                                                                    
                    except socket.error as socketerror:                                                                                                                                                                        
                           lgr.error("Socket Error: %s ", (socketerror))
                           time.sleep(1.0)
                           if socketerror.errno==errno.EPIPE:                              
                               lgr.critical('Connection  ...EPIPE..') ;pass
                           elif  socketerror.errno==errno.ECONNRESET :                    
                                lgr.critical('Connection reset ...ECONNRESET ..') ;pass                                             
                           elif socketerror.errno==errno.ECONNREFUSED : 
                               lgr.critical('Connection refused ......');self.recon_do_work(ever=True)                 
                                                                             
                           elif socketerror.errno == errno.ECONNABORTED: 
                               lgr.critical('Connection ECONNABORTED ......');pass
                           elif socketerror.errno == errno.EWOULDBLOCK:  # timeout condition if using SO_RCVTIMEO or SO_SNDTIMEO
                               lgr.critical('Connection EWOULDBLOCK......');pass
                           elif (socketerror.errno  == errno.ENETRESET) or (socketerror.errno  == errno.ETIMEDOUT):
                                lgr.critical('Connection reset ....ENETRESET .. ETIMEDOUT))  ..') ;pass  
                           else:
                               lgr.error('Socket not response... disconnection, it can timeout processing/freeze/close')                           
                               time.sleep(1.0)
                               if socketerror.errno== errno.ECONNREFUSED: 
                                   lgr.critical('Connection refused ......'); self.recon_do_work(ever=True)               
                                              
                               
                               else :
                                   if fuzz_session.socket_flag==False :
                                        fuzz_session.stimeout=1 #first time, count t out ,counter   10
                                        fuzz_session.socket_flag=True #enable counter
                                        fuzz_session.num=fuzz_session.num_of_request
                                            
                                   #i already have a measurement, i look if it is continuous, socket_flag==False
                                   elif (fuzz_session.num_of_request-1 == fuzz_session.num) and (fuzz_session.stimeout!=10):  #self.stimeout=10 replace                                 
                                        fuzz_session.stimeout += 1
                                        fuzz_session.num=fuzz_session.num_of_request
                                        if (fuzz_session.stimeout==10) : #self.stimeout=10 replace
                                            lgr.info('')
                                            lgr.critical('Connection it lost after %d request..Socket connect failed!'%fuzz_session.stimeout)
                                            fuzz_session.stimeout=0
                                            fuzz_session.socket_flag=False;self.recon_do_work(ever=True)
                                            time.sleep(1.0)
                                   else:
                                        fuzz_session.socket_flag=False
                                        fuzz_session.num=0                            
                    #default for detect error as er
                    except  Exception as er:                                                                  
                           lgr.error(er);lgr.error('Exit and try creating socket again')                                           
                           time.sleep(1.0)
                           pass # in process normal no  # traceback.print_exc()    
                           #break  # in process   with traceback.print_exc()                                                    
                                                                                                                                              
                lgr.info("Finally! . Fuzzer all DONE !!.")
                fuzz_session.master1.close()                                

class process():
               
    '''
    Chooses an item from a list defined as priority:
    [(item_1,priority_1), (item_2,priority_2),... ,(item_priority_n)]
    where priority_i is the priority of choosing item_i
    
    '''    
    
    def priority_choice(self,items):
      
       priority_choice = fuzz_session.priority
       for item, priority in items:
          if (priority==priority_choice) :
             return item
          item=0
       return item  
                   
    
    def init_new_session(self,pdu,slave):
       """
       When a new pdu is detected, the fuzzer also starts
       a new session, i.e.  + Num of request
       """
       lgr.info('');F_session = Fuzz_session()                                                  
       fuzz_session.num_of_request += 1
       if fuzz_session.test_format in (0,1,2) and fuzz_session.priority==2:change_test_format()  # in ifuzzer.py
       
       lgr.info('\t New request ------> %d',fuzz_session.num_of_request)      
       F_session.fuzz = self.priority_choice(test_suites_list) 
          
       if F_session.fuzz == 'test_message_PDU':                    
          lgr.info('Prepare to fuzz testing format message')
          adu,pdu=basetest.test_illegal_PDU().fuzz_payload(pdu)  #basetest.test_illegal_PDU() , module _init_
          return adu,pdu        
       elif F_session.fuzz == 'test_MBAP':
          lgr.info('Prepare to fuzz testing fields in MBAP')
          adu=basetest.fuzz_test_MBAP().fuzz_field_mbap(pdu,slave)
          return adu,pdu         
       elif F_session.fuzz == 'test_field_PDU':
          lgr.info('Prepare fuzz testing fields in PDU')
          adu,pdu=basetest.fuzzer_pdu().fuzz_field_pdu(pdu)
          return adu,pdu 
       elif F_session.fuzz == 'Not_fuzz':
          lgr.info('Prepare fuzz None')
          adu,pdu=basetest.fuzzer_None().fuzz_field_None(pdu)
          return adu,pdu
       elif F_session.fuzz == 'Serial_FC':
          lgr.info('Prepare Serial_FC')
          pass
                                                                                                                                                                                   
def do_work(forever=True):
    """
    The main fuzzer function,start with a socket at 1-second timeout,set parametre host 

    """
    global num_of_request,host
    
    while True:
        MAXIMUM_NUMBER_OF_ATTEMPTS=3
        # 
        lgr.info ("Creating the socket host %s"%host)
        fuzz_session.master1.__init__(host=host, port=502, timeout_in_sec=1.0)
           
        for attempt in range(MAXIMUM_NUMBER_OF_ATTEMPTS):             
            try:           
                fuzz_session.master1.open_b()
                lgr.info('Socket connect worked!') ;start_fuzzer()                 
                                   
            # except EnvironmentError as exc:
            except socket.error as socketerror:
                lgr.error("Socket Error: %s ", (socketerror))
                lgr.error('Socket connect failed! Loop up and try socket again')               
                time.sleep(1.0); continue                      
        else :
            lgr.error('maximum number of unsuccessful attempts reached : %d' % MAXIMUM_NUMBER_OF_ATTEMPTS)                       
            lgr.info("Fuzzer terminate !!.");fuzz_session.master1.close();sys.exit(1)
            
def start_fuzzer():
    """ 
    Initializing Fuzzer started, start time for duration time
    Initializing fuzz_operation dictionary
    Read csv file for config  fuzzer/calc fuzz address list from class list_of_fuzz 
    p=dict_fuzz_object()
    p.int_fuzz_operation()
    rw_obj=libraries.Rw_object_info(),  

    """
    global running,fuzz_mode,search_mode,start_time,end_time,num_of_request,pcap_mode
    start_time = datetime.now()
    p=libraries.dict_fuzz_object();p.int_fuzz_operation() #libraries.
    rw_obj=libraries.Rw_object_info()                           
    lgr.info('Initializing fuzz log reader and fuzzing operation dictionary');lgr.info('Fuzzer started ')
    
    # phese I Search FC and address
    if fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode==False:
            lgr.info('Running in search_mode !')         
            b_box=basetest.black_box()             # object for scan  function support ans map address
            b_box.con_SUT()                        # run test black box                                  
            info(start_time,num_of_request)        # info time and request 
            sys.exit(1)                                        
            
    elif  fuzz_session.search_mode==True and fuzz_session.fuzz_mode==False and fuzz_session.pcap_mode== True :
            lgr.info('Running  in search mode and pcap mode!')
            b_box=basetest.black_box_pcap()       # object for scan  function support ans map address         
            b_box.con_SUT_pcap()                  # read pcap file and add info in csv file          
            info(start_time,num_of_request)
            sys.exit(1)   
    
    #fuzzer operation querie, search_mode False from command line 
    elif  fuzz_session.search_mode==False and fuzz_session.fuzz_mode==True and fuzz_session.pcap_mode== False:      
            lgr.info('Running in fuzzing mode')
            rw_obj.Read_CSvFile()                 # read file csv and append list for configuration          
            s=SetupAndTeardown()                  # object for fuzzer            
            s.con() 
            info(start_time,num_of_request)       # info time and request             
            sys.exit(1)                                       
    
    #run test black box 
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==False:
            
            lgr.info('Running in search mode and fuzzing mode')
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False
            b_box=basetest.black_box()            # object for scan  function support ans map address
            b_box.con_SUT()                       # run test black box 
            
            #run fuzzer mode and read csvFile
            lgr.info("\n \t \t \t \t Fuzz testing running ...")
            fuzz_session.search_mode=False
            fuzz_session.fuzz_mode=True            
            rw_obj.Read_CSvFile()                 # read file csv and append list for configuration
            s=SetupAndTeardown()                  # object for fuzzer            
            s.con()                               # fuzzer querie 
            info(start_time,num_of_request)       # info time and request 
            sys.exit(1) 
    
    elif fuzz_session.fuzz_mode==True and fuzz_session.search_mode==True and fuzz_session.pcap_mode==True :
            """run read from pcap file """ 
            
            lgr.info('Running in search mode and fuzzing mode, info read from pcap file')                          
            fuzz_session.search_mode=True
            fuzz_session.fuzz_mode=False
            b_box=basetest.black_box_pcap()        # object for scan  function support ans map address     
            b_box.con_SUT_pcap()                   # read pcap file and add info in csv file 
                                      
            """run fuzzer mode and read csvFile"""
            lgr.info("\n \t \t \t \t Fuzz testing running ...")
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
      print(sys.argv[0], '-i <host>  -s <search_mode> -z <fuzz_mode> -f <csvFile=search.csv> -p <pcap file=packets.pcap> -t <suite test> -w  <x-way test> -F  <format test> -r <normal request> ')   

 
def main():
   """
   The main function, reads the fuzzer arguments and starts the fuzzer
   create a directory if it does not exist, log_dir=./log 
   o == option
   a == argument passed to the o
   test_suites = [('test_MBAP', 1.0), ('test_format', 2.0), ('test_field_PDU', 3.0),('Not_fuzz',4.0)]
   e.g python3 mtf.py -i 127.0.0.1  -z -f -t 1 -w 1 for MBAP test, single test
   
   from defines.py
   host=None       
   log_dir = "./log/"
   log_file=""
   slave=1

   """

   global host, log_dir,log_file,fuzz_mode,search_mode,filename,slave

   pcap_file="packets.pcap" 

   try : 
       opts, args = getopt.getopt(sys.argv[1:], 'i:se:ze:pe:fe:t:r:w:F:')
   except getopt.GetoptError as err:
       print(str(err));print_usage(); sys.exit(0)

   for o, a in opts:
      print(o, a)
      
      if o == '-i':
         host = a
      
      elif o == '-s':
         fuzz_session.search_mode = True

      elif o == '-p':
        #pcap_file="packets.pcap"                     
         fuzz_session.pcap_mode = True
                                                           
      elif o == '-f':
         csvFile="search.csv"                
                    
      elif o == '-z':
         fuzz_session.fuzz_mode = True

      #define suite test each FC,  suite test 0 all suite test >future
      elif o == '-t':         
         fuzz_session.priority = int(a)

      #define, send rormal request 1000 defaults
      elif o == '-r':         
          fuzz_session.normal_request = int(a)
      
      #In test_field, if way=1 single, way=2 pairwise , way=0 single and pairwise (defaults)
      elif o == '-w':         
          fuzz_session.way = int(a)

       #In test_field, if fo=1 test_dumplicate_ADU, fo=2 attack_byte_PDU, (defaults) fo=0 all test
      elif o == '-F':         
          fuzz_session.test_format = int(a)    

      else: 
         assert False, "unhandled option"  
                      
   lgr.info('SUT Unit IP address: ' + host )
   lgr.info('Slave/Unit ID: %d', slave )
   lgr.info('Stopping: Ctrl+c ')                            
   lgr.info('path log file info: '+ log_dir + filename1)
   lgr.info('path log file error: '+ log_dir + filename2 )
   lgr.info('csvFile: ' + "./" + csvFile)                         
   lgr.info('pcap_file: ' + "./" + pcap_file) 
   lgr.info('Choice suite test for each FC: %d' %fuzz_session.priority)
   lgr.info('Case 4 normal request for each FC: %d',fuzz_session.normal_request)
   lgr.info('Single or pairwise test of fields: %d',fuzz_session.way)
   lgr.info('Test illegal PDU: %d',fuzz_session.test_format)
     
   #if fuzz_session.way  or fuzz_session.test_format ==0 all test run 
   if(host is None  or csvFile == "" or log_dir==""): print_usage(); sys.exit(0)
   
   elif ((fuzz_session.priority not in  (1, 2, 3, 4) or fuzz_session.way not in (0, 1, 2) or fuzz_session.test_format not in (0,1,2)) and fuzz_session.fuzz_mode==True) :
      print_usage(); sys.exit(0)
     
   elif (fuzz_session.search_mode==False and fuzz_session.fuzz_mode==False):
      print_usage() ;sys.exit(0)

   elif (fuzz_session.priority==2 and fuzz_session.way in (1,2)): # case test_format  but use -w (way=1 single, way=2 pairwise) 1 or 2 
      print_usage() ;sys.exit(0)

   elif (pcap_file != "" and csvFile != ""): 
        if fuzz_session.pcap_mode== True:
           start_fuzzer()    #fuzz_session.pcap_mode = True not start with a socket 
        else :do_work(True)  #start with a socket at 1-second timeout,set parametre host and start_fuzzer      
            
   else:print_usage(); sys.exit(0)
   

if __name__ == "__main__":

    signal.signal(signal.SIGINT, signal_handler)
    Cleaning_up()                                             # Cleaning up  log files in dir ./ demo temp
    fuzz_session.master1 = modbus_tcp_b.TcpMaster_b()         # set param master1         object  
    log_info(lgr,logger)

    main() 
    
    
    
    
    
