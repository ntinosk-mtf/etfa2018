#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
From  Modbus TestKit: Modbus tk
This is distributed under GNU LGPL license, see license.txt
"""

import threading,logging
import socket
import select
import modbus_tk.utils as utils
import fuzz_session
import logging.handlers as handlers
from raise_except import (CsvError,TestfieldError) #exception for raise_except  

# create logger- 
lgr=logging.getLogger('')

def threadsafe_fun(fcn):
    """decorator making sure that the decorated function is thread safe"""
    
    lock = threading.Lock()
    def new(*args, **kwargs):
        """lock and call the decorated function"""
        lock.acquire()
        try:
            ret = fcn(*args, **kwargs)
        except Exception as excpt:
            raise excpt
        finally:
            lock.release()
        return ret
    return new

def flush_socket_b(socks, lim=0):
    """remove the data present on the socket"""
    
    input_socks = [socks]
    cnt = 0
    while 1:
        i_socks, o_socks, e_socks = select.select(input_socks, input_socks, input_socks, 0.0)
        if len(i_socks)==0:
            break
        for sock in i_socks:
            sock.recv(1024)
        if lim>0:
            cnt += 1
            if cnt>=lim:
                #avoid infinite loop due to loss of connection
                raise Exception("flush_socket: maximum number of iterations reached")
                
def get_log_buffer_b(prefix, buff):
    """Format binary data into a string for debug purpose"""
    
    log = prefix
    for i in buff:
        log += str(ord(i)) + "-"
    return log[:-1]  


def reset_fuzzer(): 
    '''
    ''' 
    fuzz_session.test_flag_fc=True               #disable//enable test FC for next FC
    fuzz_session.flag_reguest=False              #Stop reguest //and fuzzer  
     

def is_way(way):
    """
    Choice single or pairwise test of fields
    if ValueError: list.remove(x): x not in list
    test_field, if way=1 single , way=2 pairwise , way=0 (defaults)
    """            
    
    if len(fuzz_session.fields_of_list) == 0:
        lgr.exception("empty list of test NEXT FC")
       
    elif way not in  fuzz_session.fields_of_list:
        lgr.exception("pairwise :{0} not found".format(fuzz_session.way))
        pass
        
    elif fuzz_session.way==1 :
        fuzz_session.fields_of_list.remove(way)
    
    elif fuzz_session.way==2 :
        fuzz_session.fields_of_list=[way]  
    
    else :#Not choice single or pairwise test of fields, test all
        pass


def not_exist_field(field): 
    """
    if problem in list of test  a field of PDU Modbus protocol each FC 
    e.g. 'test_field_read_fc':['address', 'quantity_of_x', '2-way']
    """
  
    lgr.warn ("test_field is {0!r} not exists, not fuzzing, next ..".format(field))
    if fuzz_session.way in (0,2) :fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) #rotate 
    #else : fuzz_session.fields_of_list.pop(0)    
    if len(fuzz_session.fields_of_list) == 0:        #next test FC
        fuzz_session.test_flag_fc=True               #disable//enable test FC for next FC
        fuzz_session.flag_reguest=False
