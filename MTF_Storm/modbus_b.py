#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
 Source code for Modbus/TCP fuzzer used for the ETFA 2015/2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr 
 Use Modbus TestKit: Implementation of Modbus protocol in python
 The modbus_tk simulator is a console application which is running a server with TCP 

"""

import sys, os, time,datetime
import struct
import threading
import modbus_tk
import modbus_tk.defines as defines
#from modbus_tk.modbus  import *
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
from modbus_tk.hooks import *
import Queue
import SocketServer
import ctypes
import modbus_tk.utils 
from modbus_tk.utils import threadsafe_function
from utils_b import *
import scapy.layers.l2
import scapy.layers.inet
from scapy.all import *

from message import *
from mtf import * 
#
DUFF=False

#-------------------------------------------------------------------------------
#Exceptions from modbus_tk
#-------------------------------------------------------------------------------

class ModbusError(Exception):
    """Exception raised when the modbus slave returns an error"""
    
    def __init__(self, exception_code, value=""):
        """constructor: set the exception code returned by the slave"""
        if not value:
            value = "Modbus Error: Exception code = %d" % (exception_code)
        Exception.__init__(self, value)
        self._exception_code = exception_code
        
    def get_exception_code(self):
        """return the exception code returned by the slave (see defines ON TOP )"""
        return self._exception_code


class FunctionNotSupportedError(Exception):
    """
    Exception raised when calling a modbus function not supported by modbus_tk
    """
    
    pass

class ModbusInvalidResponseError(Exception):
    """
    Exception raised when the response sent by the slave doesn't fit 
    with the expected format
    """    
    
    """constructor: set the exception code returned by the slave"""
           
    pass   
          
        
class Master_b(modbus.Master):
    """
    This class implements the Modbus Application protocol for a master
    To be subclassed with a class implementing the MAC layer
    """

    def __init__(self,timeout_in_sec, hooks=None):
        """Constructor"""
        modbus.Master.__init__(self,timeout_in_sec,hooks=None)

    
    def open_b(self):
        """open the communication with the slave"""
        if not self._is_opened:
            self._do_open_b()
            self._is_opened = True    

    def _send_b(self, buf):
        """Send data to a slave on the MAC layer"""
        raise NotImplementedError()    

     
    @threadsafe_fun
    def execute_master(self,slave,pdu,expected_length=-1):
        ''' instantiate a query which implements the MAC (TCP or RTU) part of the protocol        
             add for use only to black-box ,  send pdu and response pdu return
        '''
        query = modbus_tcp_b.TcpQuery_b()
        request = query.build_request_blackbox(pdu, slave)  
        lgr.info('request pdu: ---> %r '% ByteToHex(pdu))

        # send the request to the slave
        retval = call_hooks("modbus.Master.before_send", (self,request))

        if retval <> None:
            request = retval
           
        if self._verbose:
            lgr.warn(utils.get_log_buffer("-> ", request))
        self._send_b(request)

        call_hooks("modbus.Master.after_send", ())
        # receive the data from the slave server
        if slave != 0:
        
            response = self._recv_b(expected_length)
            retval = call_hooks("modbus.Master_b.after_recv", (self, response))
            if retval <> None:
                response = retval
                
            if self._verbose:
                lgr.warn(utils.get_log_buffer("<- ", response))
            # extract the pdu part of the response
            response_pdu = query.parse_response_b(response)
           
        return response_pdu 

    

    """Add for  memory dump attacks  implementation  Execute a modbus query and returns the data part of the answer -----------""" 
   
    def execute_read_memory(self, slave, function_code, address_read, quantity_of_x=0, output_value=0, data_format="", expected_length=-1):
            """
            Execute a modbus query and returns the data for fuzzer
            """
            import fuzz_session                             #INSERT fuzz_session.fuzz_mode , fuzz_session.search_mode          
            pdu = ""
            request=""
            is_read_function = False
            
            #open the connection if it is not already done
            self.open()           
            #Build the modbus pdu and the format of the expected data.
            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, address_read, quantity_of_x)
                byte_count = quantity_of_x / 8
                if (quantity_of_x % 8) > 0:
                    byte_count += 1
                nb_of_digits = quantity_of_x
                if not data_format:    
                    data_format = ">"+(byte_count*"B")
                if expected_length < 0:               #No lenght was specified and calculated length can be used:
                    expected_length = byte_count + 5  #slave + func + bytcodeLen + bytecode + crc1 + crc2

            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, address_read, quantity_of_x)
                if not data_format:
                    data_format = ">"+(quantity_of_x*"H")
                if expected_length < 0:                    #No lenght was specified and calculated length can be used:
                    expected_length = 2*quantity_of_x + 5  #slave + func + bytcodeLen + bytecode x 2 + crc1 + crc2                 
           
            else:
                lgr.info('The %d function code is not supported.' % function_code)
                pass
            
            if (fuzz_session.search_mode==True) and (fuzz_session.fuzz_mode==False):            # search False /fuzzer mode
                """for fuzzer object"""  
                query = modbus_tcp_b.TcpQuery_b()
                request = query.build_request_blackbox(pdu, slave)                                                                      
                #lgr.info(' request Modbus message : -----> %r ' % ByteToHex(request))           #request  to SUT                                                      
                # send the request to the slave
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                             #in modbus_tcp_b 
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.debug(utils.get_log_buffer("<- ", response))
                    # extract the pdu part of the response
                    if response=='':
                        lgr.warn('Fuz_address %s , response Modbus message :  %r' % (address_read, ByteToHex(response)))
                        return response
                    else :         
                        #lgr.info('Fuz_address %s , response Modbus message : %r' % (address_read, ByteToHex(response))) #demo
                        #extract the pdu part of the response
                        response_pdu = query.parse_response_b(response)
                        
                        """analyze the received data Response message analyzer"""
                        (return_code, byte_2) = struct.unpack(">BB", response_pdu[0:2])
                        if return_code >= 128:                   
                                exception_code = byte_2
                                if 1 <= exception_code<= 4:                                       # exception Code out of specifications !!!!
                                    lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                                    #raise ModbusError(exception_code)
                                    return lgr.info('Answer >> First address_read %s response %r '  % (address_read,(return_code, byte_2)))
                                else : 
                                    lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                                    return lgr.info('Answer >> First address_read %s response %r '  % (address_read,(return_code, byte_2)))              

                        elif return_code!= function_code :
                            lgr.critical("ModbusError(not specifications)!! >>return_code=%d- request_function code=%d" % (return_code,function_code ))   
                            return lgr.info('Answer >> First address_read %s response %r '  % (address_read,ByteToHex(response)))              

                        else:
                            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:                               
                                # get the values returned by the reading function
                                data_format = ">"+(byte_count*"B")
                               
                                data = response_pdu[2:]
                                if byte_count != len(data):                 # if response byte is request 
                                    # the byte count in the pdu is invalid
                                    lgr.critical("ModbusInvalidResponseError >> Wall_Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.critical('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+(len(data)*"B")         # if  byte_2=0                       
                                    result=""
                                    if len(data) !=0 :
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    return result 
                            
                            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                                # get the values returned by the reading function
                                #byte_count = struct.unpack(">BB", request_pdu[0:2])  fuzz_byte count
                                nb_of_digits=0
                                data = response_pdu[2:]
                                byte_count = byte_2                                   #RESPONSE byte count                                
                                                                                            
                                data_format = ">"+((byte_count/2)*"H")
                                
                                
                                if len(data) <= 1 :
                                    return lgr.error('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))                         # not register len (16bit)    
                               
                                if byte_count != len(data):                 # if response byte is request 
                                    # the byte count in the pdu is invalid
                                    lgr.critical("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                    #byte_count=byte_2                        #set byte count response and calculate
                                    lgr.critical('Answer >> First address_read %s ,fc %d ,response %r '  % (address_read,return_code, ByteToHex(response)))
                                    #returns the data as a tuple according to the data_format
                                    #(calculated based on the function or user-defined)
                                    data_format = ">"+((len(data)/2)*"H")                                                  
                                    result=""
                                    z=(len(data)-1)                                    
                                    if len(data) !=0 and len(data) >= 2 :
                                        data = response_pdu[2:2+z]                         # module /2  1 byte apomeni
                                        result = struct.unpack(data_format, data)
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)
                                    else :
                                        pass    
                                        
                                    #return lgr.error('Answer >> Fuz_address %s result  %r '  % (address_read,result))
                                    return result

                            # returns what is returned by the slave after a writing function /return tumple (results)                                   
                            
                            #returns the data as a tuple according to the data_format
                            #(calculated based on the function or user-defined)
                            #data_format=">HH"
                            result = struct.unpack(data_format, data)
                            if nb_of_digits > 0:
                                digits = []
                                for byte_val in result:
                                    for i in xrange(8):
                                        if (len(digits) >= nb_of_digits):
                                            break
                                        digits.append(byte_val % 2)
                                        byte_val = byte_val >> 1
                                result = tuple(digits)
                                                                
                            return result
                        
            else  :
                print >>sys.stderr, 'Problem'
                return       

    """Add for implementation  Define function code Modbus_tk for use to fuzzer/Execute a modbus query and returns the data part of the answer -----------""" 
 
    def execute_f(self, slave, function_code, starting_address, quantity_of_x=0, output_value=0, data_format="", expected_length=-1):
            """
            Execute a modbus query and returns the data for fuzzer
            """
            import fuzz_session                             #insert fuzz_session.fuzz_mode , fuzz_session.search_mode          
            pdu = ""
            reguest=""
            is_read_function = False
            
            #open the connection if it is not already done
            self.open()           
            #Build the modbus pdu and the format of the expected data.
            #It depends of function code. see modbus specifications for details.
            if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                byte_count = quantity_of_x / 8
                if (quantity_of_x % 8) > 0:
                    byte_count += 1
                nb_of_digits = quantity_of_x
                if not data_format:    
                    data_format = ">"+(byte_count*"B")
                if expected_length < 0:                           #No lenght was specified and calculated length can be used:
                    expected_length = byte_count + 5              #slave + func + bytcodeLen + bytecode + crc1 + crc2

            elif function_code == READ_INPUT_REGISTERS or function_code == READ_HOLDING_REGISTERS:
                is_read_function = True
                pdu = struct.pack(">BHH", function_code, starting_address, quantity_of_x)
                if not data_format:
                    data_format = ">"+(quantity_of_x*"H")
                if expected_length < 0:                           # No lenght was specified and calculated length can be used:
                    expected_length = 2*quantity_of_x + 5          #slave + func + bytcodeLen + bytecode x 2 + crc1 + crc2

            elif (function_code == WRITE_SINGLE_COIL) or (function_code == WRITE_SINGLE_REGISTER):
                if function_code == defines.WRITE_SINGLE_COIL:
                    if output_value != 0:
                        output_value = 0xff00
                pdu = struct.pack(">BHH", function_code, starting_address, output_value)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                     #No lenght was specified and calculated length can be used:
                    expected_length = 8                      #slave + func + adress1 + adress2 + value1+value2 + crc1 + crc2

            elif function_code == WRITE_MULTIPLE_COILS:
                byte_count = len(output_value) / 8
                if (len(output_value) % 8) > 0:
                    byte_count += 1
                pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count)
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
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                          #No lenght was specified and calculated length can be used:
                    expected_length = 8                          #slave + func + adress1 + adress2 + outputQuant1 + outputQuant2 + crc1 + crc2

            elif function_code == WRITE_MULTIPLE_REGISTERS:
                byte_count = 2 * len(output_value)
                pdu = struct.pack(">BHHB", function_code, starting_address, len(output_value), byte_count)
                for j in output_value:
                    pdu += struct.pack(">H", j)
                if not data_format:
                    data_format = ">HH"
                if expected_length < 0:                         #No lenght was specified and calculated length can be used:
                    expected_length = 8                         #slave + func + adress1 + adress2 + outputQuant1 + outputQuant2 + crc1 + crc2                  
           
            else:
                lgr.info( 'The %d function code is not supported.' % function_code)
                pass
               
                 
            """Reconnaissance-black box search-for mapping address-instantiate a query which implements the MAC (TCP or RTU) part of the protocol/for mapping address """
            if  (fuzz_session.search_mode== True) and (fuzz_session.fuzz_mode==False):                             
            
                query = modbus_tcp_b.TcpQuery_b()
                request = query.build_request_blackbox(pdu, slave)                                                       
                # send the request to the slave
                lgr.info('The request Modbus message : %r ' % ByteToHex(request))     
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.debug(utils.get_log_buffer("-> ", request))             
                # self._send_b(request)-->>>in modbus_tcp_b
                self._send(request)                                  
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.debug(utils.get_log_buffer("<- ", response))
                    # extract the pdu part of the response
                    response_pdu = query.parse_response_b(response)
                    
                return response_pdu          
            
              
            elif (fuzz_session.search_mode==False) and (fuzz_session.fuzz_mode==True):                            
                
                """Case for fuzzer object, Fuzz request to SUT  """ 
                
                query = modbus_tcp_b.TcpQuery_b()                                                                      
                request = query.build_request_b(pdu, slave)                                                                                     
                lgr.info('The request Modbus message at 260 Hex : --> %r ' % ByteToHex(request[:260]))                                                   
                #PDU after fuzz test- send the request to the slave
                pdu=request[7:]                                                           
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.warn(utils.get_log_buffer("-> ", request))             
                #send_b, in modbus_tcp_b 
                self._send_b(request)                                                     
                call_hooks("modbus.Master.after_send", (self))
                
                # receive the data from the slave  and parse 
                if slave != 0:
                    
                    response = self._recv_b(expected_length)                              
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.error(utils.get_log_buffer("<- ", response))
                    #test case test_message_PDU',
                    if fuzz_session.priority==4 :
                        #test start addreess case test PDU field
                        lgr.info('response Modbus message : %r' % (ByteToHex(response)))                
                        # extract the pdu part of the response
                        if response=='':
                            #lgr.critical('not response fuzz_session.quantity_of_x: %d' % fuzz_session.quantity_of_x)           #demo
                            lgr.critical('response Modbus message : %r' % (ByteToHex(response))) 
                            return response

                    if fuzz_session.priority==3 or fuzz_session.priority==2 or fuzz_session.priority==1 :    
                        #test start addreess case test PDU field
                        lgr.info('fuzzing address %s , response Modbus message : %r' % (fuzz_session.starting_address, ByteToHex(response)))                                 
                        # extract the pdu part of the response
                        if response=='':
                            #lgr.info('The request Modbus message (until 28 Hex Byte ) : %r ' % ByteToHex(request[:28]))
                            lgr.critical('fuzzing address %s , response Modbus message :  %r' % (fuzz_session.starting_address, ByteToHex(response))) 
                            return response
                    
                        #extract the pdu part of the response/analyze the received data Response message analyzer"""
                        else :         
                            response_pdu = query.parse_response_b(response)
                            
                            if len(response_pdu)<2:
                                lgr.critical("ModbusError(not specifications)!! >>return_code and exception Code bad %r" %response_pdu) 
                                return response_pdu   
                            else :
                                (return_code,byte_2) = struct.unpack(">BB", response_pdu[0:2])

                            #base chech for log files in the  exception Code out of specifications, valid  exception Code  = ∈ {01,02,03,04}
                            if return_code >= 128:                   
                                    exception_code = byte_2
                                    if return_code>128 and (1 <= exception_code<= 4):                                       
                                        lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2)) 
                                        return lgr.info('Answer >> Fuz_address %s response %r '  % (fuzz_session.starting_address,(return_code, byte_2)))
                                    
                                    elif  return_code==128 and exception_code>=0:         
                                        lgr.error("ModbusError (not specifications) >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                                        lgr.warn('Answer >> Fuz_address %s response %r '  % (fuzz_session.starting_address,(return_code, byte_2))) 

                                    else : 
                                        lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                                        lgr.warn('Answer >> fuzzing address %s response %r '  % (fuzz_session.starting_address,(return_code, byte_2))) 
                                        return lgr.info('Answer >> Fuz_address %s response %r '  % (fuzz_session.starting_address,(return_code, byte_2)))              

                            elif return_code!= function_code :
                                lgr.critical("ModbusError(not specifications)!! >>return_code=%d- request_function code=%d" % (return_code,function_code ))   
                                lgr.critical('Answer >> fuzzing address %s response %r '  % (fuzz_session.starting_address,ByteToHex(response)))
                                return lgr.info('Answer >> fuzzing address %s response %r '  % (fuzz_session.starting_address,(return_code,function_code )))              
                                
                            elif return_code==function_code and len(response_pdu)==2:
                                lgr.critical('Answer >> fuzzing address %s response %r '  % (fuzz_session.starting_address,ByteToHex(response)))
                                return lgr.info('Answer >> fuzzing address %s response (fc, Byte) %r '  % (fuzz_session.starting_address,(return_code,response_pdu)))              
                                    
                            else:
                                if function_code == READ_COILS or function_code == READ_DISCRETE_INPUTS:                               
                                    # get the values returned by the reading function
                                    byte_count=byte_2 
                                    data_format = ">"+(byte_count*"B")
                                    data = response_pdu[2:]
                                    #compare byte_count and len of data-quantity_of_x>2000/8=250   
                                    if  (byte_count != len(data) or len(data)==0 or len(data)>250 ):                                   
                                        # the byte count in the pdu is invalid
                                        lgr.critical("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d. " % (byte_count, len(data)))                                    
                                        #byte_count=byte_2                        #set byte count response and calculate
                                        lgr.critical('Answer >> fc %d, Fuz_address %s, fuz_quantity_of %d, response %r '  % (return_code,fuzz_session.starting_address,fuzz_session.quantity_of_x, ByteToHex(response)))
                                        #returns the data as a tuple according to the data_format
                                        #(calculated based on the function or user-defined)
                                        data_format = ">"+(len(data)*"B")                             # case  byte_2=0                       
                                        result=""
                                        if len(data) !=0 :
                                            result = struct.unpack(data_format, data)
                                            if nb_of_digits > 0:
                                                digits = []
                                                for byte_val in result:
                                                    for i in xrange(8):
                                                        if (len(digits) >= nb_of_digits):
                                                            break
                                                        digits.append(byte_val % 2)
                                                        byte_val = byte_val >> 1
                                                result = tuple(digits)
                                                #check boundaries for FC, fuzz_session.flag_boundaries check address+quantity
                                                if (fuzz_session.quantity_of_x>2000 or fuzz_session.quantity_of_x==0 \
                                                   or fuzz_session.flag_boundaries==1) :
                                                   return lgr.critical('Answer >> illegal_quantity_of %d, Fuz_address %s result  %r '  % (fuzz_session.quantity_of_x,fuzz_session.starting_address,result))
                                                
                                        return lgr.info('Answer >> Fuz_address %s result  %r '  % (fuzz_session.starting_address,result)) 
                                    
                                elif function_code == READ_INPUT_REGISTERS or function_code ==READ_HOLDING_REGISTERS:

                                    #get the values returned by the reading function
                                    nb_of_digits=0
                                    data = response_pdu[2:]
                                    #response byte count
                                    byte_count = byte_2                                                                                                                                                                   
                                    data_format = ">"+((byte_count/2)*"H") 
                                    
                                    if len(data) <= 1 :
                                        return lgr.critical('Answer not Value data>> Fuz_address %s ,fc %d ,response %r '  % (fuzz_session.starting_address,return_code, ByteToHex(response)))                            
                                    # if response byte is request
                                    if byte_count != len(data) or len(data)==0 or len(data)>250:                  
                                        lgr.critical('len(data)/2 %d' % (len(data)/2))
                                        # the byte count in the pdu is invalid
                                        lgr.critical("ModbusInvalidResponseError >> Byte count is %d while actual number of bytes is %d registers %d " % (byte_count, len(data), (len(data)/2)))                                    
                                        #byte_count=byte_2 set byte count response and calculate
                                        lgr.critical('Answer >> fc %d , Fuz_address %s,fuz_quantity_of %d, response %r '  % (return_code,fuzz_session.starting_address,fuzz_session.quantity_of_x, ByteToHex(response)))                                                                                                                     
                                        result=""
                                        data_format = ">"+((len(data)/2)*"H")                             # case  byte_2=0                                          
                                        if len(data) !=0 and len(data) >= 2 :                                                                                           
                                            result = struct.unpack(data_format, data[:2*(len(data)/2)])                                              #      
                                            if nb_of_digits > 0:   
                                                digits = []
                                                for byte_val in result:
                                                    for i in xrange(8):
                                                        if (len(digits) >= nb_of_digits):
                                                            break
                                                        digits.append(byte_val % 2)
                                                        byte_val = byte_val >> 1
                                                result = tuple(digits)
                                                    #check boundaries for FC, fuzz_session.flag_boundaries check address+quantity                                                   
                                                if (fuzz_session.quantity_of_x==0) or (fuzz_session.quantity_of_x>123) \
                                                    or (fuzz_session.flag_boundaries==1):
                                                    return (lgr.critical('Answer >> Fuz_address %s quantity %d result  %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,result)))
                                        return (lgr.warn('Answer >> Fuz_address %s quantity %d result  %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,result)))

                                # returns what is returned by the slave after a writing function /return tumple (results)       
                                elif (function_code == WRITE_MULTIPLE_REGISTERS) or (function_code == WRITE_MULTIPLE_COILS) : 
                                    nb_of_digits=0
                                    data = response_pdu[3:]
                                    byte_data=len(data)
                                    # 2 BYTE   MAX 1968 COIL/ 123 REG
                                    (Quantity_of_Registers, ) = struct.unpack(">H", response_pdu[3:5])        
                                    
                                    data_format = ">"+((byte_data/2)*"H")
                                    if  len(data) ==0 or len(data) < 2 :
                                         return lgr.critical('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (fuzz_session.starting_address,return_code, ByteToHex(data)))
                                    #if  return_code  bad
                                    else :
                                        if (return_code == WRITE_MULTIPLE_REGISTERS) or (return_code == WRITE_MULTIPLE_COILS) :
                                            pass
                                        else :
                                            return lgr.critical('ModbusInvalidResponseError/bad code >> Fuz_address %s ,return_code %d ,data %r '  % (fuzz_session.starting_address,return_code, ByteToHex(data)))
                                                                       
                                        #returns the data as a tuple according to the data_format
                                        #(calculated based on the function or user-defined)
                                        result = struct.unpack(data_format, data[:2*(len(data)/2)])
                                        if nb_of_digits > 0:
                                            digits = []
                                            for byte_val in result:
                                                for i in xrange(8):
                                                    if (len(digits) >= nb_of_digits):
                                                        break
                                                    digits.append(byte_val % 2)
                                                    byte_val = byte_val >> 1
                                            result = tuple(digits)                                                       #tuple, how register/or coil write N*2H
                                            
                                        #compare byte count request and quantity of coil/register to write
                                        if Quantity_of_Registers !=  int(''.join(map(str,result))) :                      # convert Tuple to Integer-int(''.join(map(str,result))
                                            lgr.critical('fuzz_quantity_of_x defer of byte count: %d' % fuzz_session.quantity_of_x)          #demo log quantity 
                                            return lgr.critical('ModbusInvalidResponseError  >> Fuz_address %s ,Quantity of Registers/coil request %d ,data %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x, result ))
                                        ##demo, check out of spec response valid case out boundaries or len,case t=3
                                        elif ((fuzz_session.quantity_of_x>123 and return_code == WRITE_MULTIPLE_REGISTERS) or \
                                            (fuzz_session.quantity_of_x>1968 and return_code == WRITE_MULTIPLE_COILS)  or fuzz_session.quantity_of_x==0 \
                                            or fuzz_session.flag_boundaries==1) :
                                            return lgr.critical('Answer out of spec >> Fuz_address: %s , quantity_of_x: %s , output_value : %s, response %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value,result))
 
                                        elif (fuzz_session.flag_len_out_of_spec==1):
                                            return lgr.critical('len is out_of_spec, answer >> Fuz_address %s response %r '  % (fuzz_session.starting_address,result))
                                        
                                        else : 
                                            return lgr.info('Answer >> Fuz_address %s response %r '  % (fuzz_session.starting_address,result))
                                        
                                elif (function_code == WRITE_SINGLE_COIL) or (function_code == WRITE_SINGLE_REGISTER) :
                                     nb_of_digits=0
                                     data = response_pdu[1:]
                                     byte_data=len(data)
                                     
                                     data_format = ">"+((byte_data/2)*"H")

                                     if  len(data) !=0 and len(data) < 4 :                                                #bad output value
                                         return lgr.critical('ModbusInvalidResponseError  >> Fuz_address %s ,return_code %d ,data %r '  % (fuzz_session.starting_address,return_code, ByteToHex(data)))
                                    
                                     else :
                                        #return tumple --fix 18.03.20-if not byte,case payload remove
                                        #if struck.unpack error 
                                        if len(pdu[3:5])!=2 or len(response_pdu[3:])!=2:
                                           return lgr.critical('ModbusInvalidResponse  >> Fuz_address %s ,send_Output_value  %r ,Return_value %r '  % (fuzz_session.starting_address,ByteToHex(pdu[3:5]), ByteToHex(data[2:])))
                                        
                                        k,=struct.unpack(">H", pdu[3:5]) 
                                        l,=struct.unpack(">H", response_pdu[3:])
                                        
                                        if (return_code == WRITE_SINGLE_COIL) : 
                                            if fuzz_session.flag_boundaries==1 or fuzz_session.mbap_error==1:
                                               return lgr.critical('Answer out of spec >> Fuz_address: %s , quantity_of_x: %s , output_value : %s'  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value))
                                                                                                                                                          
                                            elif (l==0 and k==0) or (l==65280 and k==65280):                                 
                                                   return lgr.info('ModbusWriteCoils valid >> Fuz_address %s ,send_Output_value  %r ,value %r '  % (fuzz_session.starting_address,ByteToHex(pdu[3:5]), ByteToHex(data[2:])))                                                   
                                            else :    
                                                   return lgr.critical('ModbusInvalidResponse  >> Fuz_address %s ,send_Output_value  %r ,Return_value %r '  % (fuzz_session.starting_address,ByteToHex(pdu[3:5]), ByteToHex(data[2:])))
                                             
                                            #elif fuzz_session.flag_boundaries==1 or fuzz_session.mbap_error==1:
                                            #   return lgr.critical('Answer out of spec >> Fuz_address: %s , quantity_of_x: %s , output_value : %s, response %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value,result))
                                        elif (return_code == WRITE_SINGLE_REGISTER) : 
                                            if fuzz_session.flag_boundaries==1 or fuzz_session.mbap_error==1:
                                               return lgr.critical('Answer out of spec >> Fuz_address: %s , quantity_of_x: %s , output_value : %s'  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value))
                                                                                                                                                          
                                           
                                            return lgr.info('Answer >> Fuz_address: %s , quantity_of_x: %s , output_value : %s'  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value))                               
                                else:#return_code  bad
                                   return lgr.critical('ModbusInvalidResponse  >> Fuz_address %s ,return_code %d ,value %r '  % (fuzz_session.starting_address,return_code, ByteToHex(data[2:])))

                                #returns the data as a tuple according to the data_format
                                #(calculated based on the function or user-defined)
                                
                                result = struct.unpack(data_format, data)
                                
                                if nb_of_digits > 0:
                                    digits = []
                                    for byte_val in result:
                                        for i in xrange(8):
                                            if (len(digits) >= nb_of_digits):
                                                break
                                            digits.append(byte_val % 2)
                                            byte_val = byte_val >> 1
                                    result = tuple(digits)                                                                      
                                #check out of spec response valid case out boundaries                                    
                                if (fuzz_session.quantity_of_x>2000 or fuzz_session.quantity_of_x==0 \
                                    or fuzz_session.flag_boundaries==1) or fuzz_session.mbap_error==1:
                                    return lgr.critical('Answer out of spec >> Fuz_address: %s , quantity_of_x: %s , output_value : %s, response %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value,result))
                                                   
                                return lgr.info('Answer >> Fuz_address: %s , quantity_of_x: %s , output_value : %s, response %r '  % (fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.output_value,result))
                               
                else  :
                    lgr.info('check response problem')
                    return    


    def execute_fpdu(self,slave,pdu,expected_length=-1):            
                """ 
                instantiate a query which implements the MAC (TCP or RTU) part of the protocol
                Add for use  new Function  for fuzzer ,eg Read Fifo Queue ,import from message.py
                """
        
                """for fuzzer object"""
               
                query = modbus_tcp_b.TcpQuery_b()                                                                           
                request = query.build_request_b(pdu, slave)                                  # request for fuzzer /return mbap+pdu                     
                response_pdu=''                    
                
                lgr.info('The request Modbus message first 260 Byte: -----> %r ' % ByteToHex(request[:260]))     # send the request to the slaveFuzz request  to SUT                                             
                pdu=request[7:]                                                                   # new add, is PDU  fuzzing request
               
                retval = call_hooks("modbus.Master.before_send", (self, request))
                if retval <> None:
                    request = retval
                   
                if self._verbose:
                    lgr.warn(utils.get_log_buffer("-> ", request))             
                self._send_b(request)                                                           #in modbus_tcp_b
                call_hooks("modbus.Master.after_send", (self))

                if slave != 0:
                    # receive the data from the slave
                    response = self._recv_b(expected_length)
                    retval = call_hooks("modbus.Master.after_recv", (self, response))
                    if retval <> None:
                        response = retval
                    if self._verbose:
                        lgr.warn(utils.get_log_buffer("<- ", response))
                    
                    # extract the pdu part of the response
                    if response=='':
                       lgr.error('response Modbus message : None')                                                                    
                       return response
                    else :
                        lgr.info('response Modbus message : %r' % ByteToHex(response))
                        response_pdu = query.parse_response_b(response)                                                                      
                        return self.dissect(pdu,response_pdu)                                       #pdu is fuzz reguest

    """  analyze the received data of function 20,21,22,23,24,43 """                         

    def dissect(self,pdu,response_pdu) :
                
                # extract the pdu part of the response
                #fuzz_session = Fuzz_session()
                nb_of_digits =0
                is_read_function = True
                data_format = ">HH"

                (function_code,)=struct.unpack('>B', pdu[0:1])
                               
                if len(response_pdu)<2:
                    lgr.critical("ModbusError(not specifications)!! >>return_code and exception Code bad %r" %response_pdu) 
                    (return_code,)=struct.unpack(">B", response_pdu[0:1])
                    return (return_code,)
                      
                else :
                    (return_code,byte_2) = struct.unpack(">BB", response_pdu[0:2])                  #extract to tumple
          
                if return_code >= 128:                   
                    exception_code = byte_2
                    if 1 <= exception_code<= 4  :                                                   # exception Code out of specifications !!!!
                        lgr.warn("ModbusWarn >>return_code=%d- exception Code=%d" % (return_code, byte_2))
                        
                        return (return_code, byte_2)
                    else : 
                        lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%d" % (return_code, byte_2))   
                        return (return_code, byte_2)                    
                
                if return_code!= function_code :
                    lgr.critical("ModbusError(not specifications)!! >>return_code=%d- request_function code=%d" % (return_code,function_code ))   
                    return (return_code,function_code)
         
                #24 (0x18) Read FIFO Queue-Test that the read fifo queue response can decode '''
                #The function returns a
                #count of the registers in the queue, followed by the queued data.
                #Up to 32 registers can be read: the count, plus up to 31 queued data registers.
                #FIFO count <=31, bad len >2x32+2+2              
                #message = byte count+ FIFO count+data
                #handle  = ReadFifoQueueResponse([1,2,3,4])
                #handle.decode(message)
                #return list of value [1,2,3,4]
                elif return_code== Read_FIFO_queue:                                                                      
                    data = response_pdu[1:]
                    (byte_c,FIFO_c)=struct.unpack(">HH", response_pdu[1:5])
                    # bad len response 
                    if len(data) <4 or len(data) >66:                                                                
                        lgr.error("Invalid len response payload: %d, FIFO Value Register error " % (len(data)))                       
                        return data
                    
                    elif byte_c==0 or byte_c!=len(response_pdu[3:]):
                        lgr.error("Invalid Byte Count: %d, FIFO Value Register error " % byte_c)                       
                        return data

                    elif FIFO_c<31 or FIFO_c/2!=len(data[5:]):
                        lgr.error("Invalid FIFO Count: %d, FIFO Value Register error " % FIFO_c)
                        return data                      
                    
                    else :    
                        lgr.info('Decode Modbus message response')
                        handle  = ReadFifoQueueResponse()
                        message = handle.decode('data')                        
                        return message                                                   
                     
                #ok decode request  update for use /17.09.2018/fix
                elif return_code== Read_File_record:
                     data = response_pdu[1:]                      
                     #bad len response legal PDU=253 bytes
                     if len(data)>252 or len(data)<7 :                                                
                         lgr.error('response malformed packet, invalid PDU len :%d ' %len(response_pdu))
                         return ByteToHex(data) 
                     
                     elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return ByteToHex(data)  
                     
                     else : 
                         handle  = ReadFileRecordResponse()                             
                         message=handle.decode(data)                                          
                         return message  
                                        
                #ok update for use /19.09.18/fix and fix from new ver mtf/09.1.20        
                elif return_code== Write_File_record :                                  
                     data = response_pdu[1:]
                     if len(data)>252 or len(data)<7:                              #bad len response legal PDU=253 bytes
                         lgr.error("response malformed packet, invalid PDU len : %d " %len(response_pdu)) 
                         return ByteToHex(data)                   
                     elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return data                      
                     elif pdu == response_pdu :                                    #compare pdu and response_pdu /look >>??? (pdu is fuzz)
                         handle  = WriteFileRecordResponse()                       #respone is ok     
                         records=handle.decode(data)                      
                     else :                                         
                         lgr.info('Decode Modbus message response')
                         handle  = WriteFileRecordResponse()                                
                         message=handle.decode(data)     
                         return message                                                                                                                                                    #compere len(record_data) and response record_data for groups
                                                                                                                                    
                #23 (0x17)-The normal response contains the data from the group of registers that were read.
                #update for use /01.04.2017/fix         
                elif return_code== Read_Write_Multiple_Registers:
                    data = response_pdu[2:] ; byte_data=len(data)                  #len data response                                                               
                    if len(pdu[3:5]) <2 :
                       lgr.critical("ModbusError!! >>response byte count=%d- Quantity to Read(byte_data) =%d- result: %r" % (byte_2 , byte_data, pdu[3:5]))
                       return pdu[3:5]
                    
                    (Read_Quantity, ) = struct.unpack(">H", pdu[3:5])              #extract to tumple /fuzz Read_Quantity request                 
                   
                    if Read_Quantity == (byte_2 /2):

                        if byte_2 == byte_data :                                   # if deff len  to byte_count/data
                            data_format = ">"+((byte_2/2)*"H")                     # is not problem 
                        else :  
                            data_format = ">"+((byte_data/2)*"H")
                            lgr.critical("ModbusError!! >>response byte count=%d- Quantity to Read(byte_data) =%d" % (byte_2 , byte_data))

                        result = struct.unpack(data_format, data)                   
                    else :                                                          # request Read Byte Count not equal response Byte Count/2               
                        data_format = ">"+((byte_data/2)*"H")
                        lgr.critical("ModbusError!! >>request_Read_Quantity=%d- Quantity to read=%d" % (Read_Quantity, byte_2 /2))
                            
                    result = struct.unpack(data_format, data[:2*(len(data)/2)])    
                    if nb_of_digits > 0:
                        digits = []
                        for byte_val in result:
                            for i in xrange(8):
                                if (len(digits) >= nb_of_digits):
                                    break
                                digits.append(byte_val % 2)
                                byte_val = byte_val >> 1
                        result = tuple(digits)                        
                    if (fuzz_session.flag_boundaries==1 or fuzz_session.mbap_error==1 or fuzz_session.quantity_to_Write>121 or fuzz_session.quantity_to_Read>125):
                        fuzz_session.flag_boundaries=0
                        return lgr.critical('Answer >> test_read_address: %r test_write_address: %r result: %r' % (fuzz_session.read_starting_address,fuzz_session.write_starting_address,result))
                         
                    return lgr.info(' Answer >> test_read_address: %r test_write_address: %r response: %r' % (fuzz_session.read_starting_address,fuzz_session.write_starting_address,result))
                                                                          
                #22 (0x16)/The normal response is an echo of the request. The response is returned after the register 
                #has been written. 
                #fuzz_session.flag_boundaries==1 case invalid address          
                elif return_code== Mask_Write_Register :
                    data = response_pdu[1:]
                    #bad len response legal
                    if len(data)!=6:                              
                         lgr.error("response malformed packet, invalid PDU len : %d " %len(response_pdu)) 
                         return ByteToHex(data)                   
                    elif len(data) <= 2 : 
                         lgr.error("ModbusError(not specifications)!! >>return_code=%d- exception Code=%r" % (return_code, data))   
                         return data                      
                    elif pdu == response_pdu :                                    #compare pdu and response_pdu
                         handle = MaskWriteRegisterResponse()                     #respone is ok ,decode int /self.adress,self.and_mask.self.or_mask    
                         message =handle.decode(data)
                         if (fuzz_session.flag_boundaries==1 or fuzz_session.mbap_error==1 ):
                             fuzz_session.flag_boundaries=0 ;lgr.critical('ModbusError message response')   
                         return message
                    else :
                         if (fuzz_session.flag_boundaries==1 or fuzz_session.mbap_error==1 ):
                             fuzz_session.flag_boundaries=0 ;lgr.critical('Decode Modbus message response') ;return ByteToHex(data)                                        
                         lgr.info('Decode Modbus message response')                                                #                          
                         return ByteToHex(data)                      
                
                    '''add serial exceptions FC '''
                
                #function_code = 0x07---The normal response contains the status of the eight Exception Status 
                elif return_code== Read_Exception_Status :
                    data = response_pdu[1:]
                    lgr.info(ByteToHex(data))
                    handle  = ReadExceptionStatusResponse()
                    message = handle.decode(data)                                         
                    return message

                #function_code =11 (0x0B) Get Comm Event Counter (Serial Line only)
                elif return_code== Get_Comm_Event_Counter:
                    data = response_pdu[1:]
                    print ByteToHex(data)
                    handle  = GetCommEventCounterResponse()
                    message = handle.decode(data)                                         
                    return message
                
                #function_code 12 (0x0C) Get Comm Event Log (Serial Line only)    
                elif return_code== Get_Comm_Event_Logs:
                    data = response_pdu[1:]
                    print ByteToHex(data)
                    handle  = GetCommEventLogResponse()
                    message = handle.decode(data)                                        
                    return message

                #function_code 17 (0x11) Report Server ID (Serial Line only)
                elif return_code== Report_Slave_Id:
                    data = response_pdu[1:]
                    print ByteToHex(data)
                    handle  = ReportSlaveIdResponse()
                    message = handle.decode(data)                                     
                    return message    

                #function_code  08 (0x08) Diagnostics (Serial Line only)    
                elif return_code==Diagnostics :
                    '''
                    Base decoder for a diagnostic response
                    param data: The data to decode into the function code
                    self.sub_function_code, self.message = struct.unpack('>HH', data)
                    Diagnostic Sub Code 21                                sub function code = 0x0015
                    \x08\x00\x15\x00\x03'),                               GetClearModbusPlus/(Get Statistics)     
                    '\x08\x00\x15\x00\x04'),                              GetClearModbusPlus/((Clear Statistics))
                    legal response         \x00\x15' + '\x00\x00' * 55)

                    '''
                    enc = response_pdu[1:]
                    if len(enc)<=1:
                        lgr.critical("malformed packet bad sub_function_code and data response %r" %ByteToHex(enc)); return (ByteToHex(enc),)
                    sub_f,=struct.unpack('>H', response_pdu[1:3])
                    #bad len response legal PDU=253 bytes, ex case \x08\x00\x15\-Diagnostic Sub Code 21 
                    if 1<len(enc)<4 or (len(enc)>4 and sub_f!=21):
                        lgr.critical("bad sub_function_code and data response %r" %ByteToHex(enc)); return (ByteToHex(enc),)
                    else: return (ByteToHex(enc),)  
                    #(len(enc)>4 and sub_f==21):return (ByteToHex(enc),)                                                     
                    # only return self.sub_function_code, self.message   
                    handle = DiagnosticStatusResponse()
                    handle.decode(enc)                                                                           
                    data = struct.pack('>H', handle.message)
                    sub_function_code = struct.pack('>H', handle.sub_function_code)                   
                    lgr.info("dec sub_function_code=%d- data=%r" % (handle.sub_function_code, ByteToHex(data)))
                    return (ByteToHex(sub_function_code),ByteToHex(data))
                
                #Read_Device_Information  FC : 43   
                elif return_code==Read_device_Identification : 
                    mei_object=[]
                    data = response_pdu[1:]
                   
                    if len(data)<6 :
                        lgr.info('response message byte less 6 byte: %r' % ByteToHex(data))
                        return data
                    
                    '''read device information MESSAGE response  decode '''       
                    handle  = ReadDeviceInformationResponse()    
                    message=handle.decode(data)   
                    #if  Object is in list ...
                    if handle.information not in  mei_object :
                          #lgr.critical('\n  \t \t Test device identification summary creation 1.....' )                
                        mei_object.append(dict(handle.information))                                                                                     
                        #return  mei_object        
                    else :
                        lgr.info('message : %r ' % ByteToHex(message))
                        return message
                    
                    if (fuzz_session.flag_boundaries==1):fuzz_session.flag_boundaries=0;lgr.critical('\n  \t \t Test device identification summary creation .....' )                        
                        #; lgr.critical("\n".join(map(str, mei_object)))                                  
                    else:   
                       lgr.info('\n  \t \t Test device identification summary creation .....' ) ;lgr.info("\n".join(map(str, mei_object)))                
                    return  mei_object                       
                else:
                    lgr.error("ModbusError(not specifications-(return_code or exception)!! >>return_code=%d- byte_2=%r" % (return_code, byte_2))          
                    return (return_code, byte_2) 

class Databank_b(modbus.Databank):
    """A databank is a shared place containing the data of all slaves"""
    def __init__(self):
        
        """Constructor""" 
        modbus.Databank.__init__(self)


    def handle_request_b(self,query,request):
        """
        when a request is received, handle it and returns the response pdu
        """
        request_pdu = ""
        
        try:
            #extract the pdu and the slave id
            (slave_id, request_pdu) = query.parse_request(request)
            #get the slave and let him executes the action
            if slave_id == 0:
                #broadcast
                for key in self._slaves:
                    self._slaves[key].handle_request(request_pdu, broadcast=True)
                return
            else:         
                slave = self.get_slave(slave_id)
                response_pdu = slave.handle_request(request_pdu)      
                lgr.info('request_pdu : ----->%r' % request_pdu)
                response = query.build_response(response_pdu)      
                lgr.info("full response hex")   
                lgr.info("\n----------------------------------------------------------------") 
          
                return response
        except Exception, excpt:
            call_hooks("modbus.Databank.on_error", (self, excpt, request_pdu))
            lgr.error("handle request failed: " + str(excpt))
        except:
            lgr.error("handle request failed: unknown error")


class Server_b(modbus.Server):
    """
    This class owns several slaves and defines an interface
    to be implemented for a TCP or RTU server
    """
    
    """Constructor""" 
    def __init__(self, databank=None):
        modbus.Server.__init__(self,databank)
        self._verbose = False
        self._thread = None
        self._go = None
        self._make_thread_b()
        

    def _make_thread_b(self):
        """create the main thread of the server"""
        self._thread = threading.Thread(target=Server_b.run_server_b, args=(self,))  #allagi
        self._go = threading.Event()


    def start_b(self):
        """Start the server. It will handle request"""
        self._go.set()
        self._thread.start()

    def stop_b(self):
        """stop the server. It doesn't handle request anymore"""
        if self._thread.isAlive():
            self._go.clear()
            self._thread.join()

    def run_server_b(self):
        """main function of the main thread"""
        try:
            self._do_init()
            while self._go.isSet():
                
                self._do_run_b()             
            lgr.info("%s has stopped" % self.__class__)
            self._do_exit()
        except Exception, excpt:
            lgr.error("server error: %s" % str(excpt))
        self._make_thread_b() 

    def handle_b(self, request):
        """handle a received sentence"""
        
        if self._verbose:
            lgr.warn(utils.get_log_buffer("-->", request))
        
        #gets a query for analyzing the request
        query = self._make_query()
        retval = call_hooks("modbus.Server.before_handle_request", (self, request))
        if retval:
            request = retval
            
        response = self._databank.handle_request_b(query, request)         #allagi
        retval = call_hooks("modbus.Server.after_handle_request", (self, response))
        if retval:
            response = retval
                
        if response and self._verbose:
            lgr.warn(utils.get_log_buffer("<--", response))
        return response
    