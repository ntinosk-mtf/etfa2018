#!/usr/bin/env python
# -*- coding: utf-8 -*-\
"""
 Source code for Modbus/TCP fuzzer used for the ETFA 2015/2018
 Code compiled by K. Katsigiannis.
 For related questions please contact kkatsigiannis@upatras.gr 
 Use:Modbus TestKit: Implementation of Modbus protocol in python
 The modbus_tk simulator is a console application which is running a server with TCP 
"""

import sys, os, time ,datetime
import socket
import threading
import struct
import select
import modbus_tk
import modbus_tk.defines as defines
import modbus_tk.modbus as modbus
import modbus_tk.modbus_tcp as modbus_tcp
from modbus_tk.hooks import *
import SocketServer
import utils_b
import modbus_b
from mtf import *
import logging


class ModbusInv_MbapError(Exception):
    """Exception raised when the modbus TCP header doesn't correspond to what is expected"""
    def __init__(self, value):
        Exception.__init__(self, value)


class TimoutException(Exception):
    '''A user-defined exception class.'''
    pass

class TcpMaster_b(modbus_tcp.TcpMaster,modbus_b.Master_b):

    def __init__(self,host='localhost',port=502, timeout_in_sec=1.0):
        """Constructor. Set the communication settings""" 
        
        modbus_b.Master_b.__init__(self, timeout_in_sec)    
        modbus_tcp.TcpMaster.__init__(self,host='192.168.1.5',port=502, timeout_in_sec=1.0)
        self._is_opened = False   
        self._sock = None
        self._host = host
        self._port = port


    def set_timeout_b(self, timeout_in_sec):
        """Change the timeout value"""
        modbus_b.Master_b.set_timeout(self, timeout_in_sec)
        if self._sock:
            self._sock.setblocking(timeout_in_sec>0)
            if timeout_in_sec:
                self._sock.settimeout(timeout_in_sec) 

    def set_keepalive(self,_sock, after_idle_sec=5, interval_sec=3, max_fails=60):
        """
        Set TCP keepalive on an open socket
        It activates after 1 second (after_idle_sec) of idleness,
        then sends a keepalive ping once every 3 seconds (interval_sec),
        and closes the connection after 60 failed ping (max_fails), or 180 seconds
        """
        _sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
        _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, after_idle_sec)
        _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, interval_sec)
        _sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, max_fails)
            

    def _do_open_b(self):
       
        if self._sock:
            self._sock.close()
        self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.set_keepalive(self._sock)                                   #new add for keepalive
        self.set_timeout_b(self.get_timeout())
        call_hooks("modbus_tcp.TcpMaster.before_connect", (self, ))
        self._sock.connect((self._host, self._port))
        call_hooks("modbus_tcp.TcpMaster.after_connect", (self, )) 
    
    def _recv_b(self, expected_length=-1):
        """
        Receive the response from the slave
        """
        response = ""
        length = 255
        
        while len(response)<length:
            # to time out return           
            try:
                # read at most 1 bytes 
                rcv_byte = self._sock.recv(1)            
               
            except socket.timeout:                
                lgr.error('Socket timeout.. not receive')
                #return response                                       
                if fuzz_session.receive_flag==False :
                        fuzz_session.receive_timeout=1 #first time, count t out ,counter   
                        fuzz_session.receive_flag=True #enable counter
                        fuzz_session.init_num_rec=fuzz_session.num_of_request
                           #i already have a measurement, i look if it is continuous, socket_flag==False
                elif (fuzz_session.num_of_request-1 == fuzz_session.init_num_rec) and (fuzz_session.receive_timeout!=10):                                   
                        fuzz_session.receive_timeout += 1
                        fuzz_session.init_num_rec=fuzz_session.num_of_request
                        
                        if fuzz_session.receive_timeout==10 : 
                            fuzz_session.receive_flag=False                                                                                                         
                            lgr.info('')
                            lgr.warn('Connection it lost after %d request..Connection it can lost..do_open !'%fuzz_session.receive_timeout);time.sleep(1.0)
                            fuzz_session.receive_timeout=0
                            self._do_open_b()
                            
                else:
                        fuzz_session.receive_flag=False
                return response  

            except socket.error, e:                               
                lgr.error("Socket Error: %s ", (e))                
                return response
                continue                           

            if rcv_byte:
                response += rcv_byte
                if len(response) == 6:
                    (tr_id, pr_id, to_be_recv_length) = struct.unpack(">HHH", response)
                    length = to_be_recv_length + 6
            else:
                break
                
        retval = call_hooks("modbus_tcp.TcpMaster.after_recv", (self, response))
        if retval <> None:
            return response
        return response       
    
    def _send_b(self, request):
        
        retval = call_hooks("modbus_tcp.TcpMaster.before_send", (self, request))
        if retval <> None:
            request = retval
        try:
            utils_b.flush_socket_b(self._sock, 3)
        except Exception, msg:                        
            self._do_open_b()
        
        if len(request)>260:
            fuzz_session.flag_len_out_of_spec=1
            lgr.error('total len request out of specifications .. !! : %d bytes' % len(request))    
        else :
            fuzz_session.flag_len_out_of_spec=0
            lgr.info('total len request : %d bytes' % len(request))
        self._sock.send(request)
     
class TcpServer_b(modbus_tcp.TcpServer,modbus_b.Server_b,modbus_b.Databank_b):
    """This class implements a simple and mono-threaded modbus tcp server"""
    
    def __init__(self,port=502, address='localhost', timeout_in_sec=1.0, databank=None):
        """Constructor: initializes the server settings"""
        
        modbus_b.Server_b.__init__(self,databank if databank else modbus_b.Databank_b())
        self._sock = None
        self._sa = (address, port)
        self._timeout_in_sec = timeout_in_sec
        self._sockets = []


    def _do_run_b(self):
        """called in a almost-for-ever loop by the server"""
        #check the status of every socket
        inputready, outputready, exceptready = select.select(self._sockets, [], [], 1.0)

        for sock in inputready: 
            try:
                if sock == self._sock:
                    # handle the server socket
                    client, address = self._sock.accept()
                    client.setblocking(0)
                    lgr.info("%s is connected with socket %d..." % (str(address), client.fileno()))
                    self._sockets.append(client)
                    call_hooks("modbus_tcp.TcpServer.on_connect", (self, client, address))
                else:
                    if len(sock.recv(1, socket.MSG_PEEK)) == 0:
                        #socket is disconnected
                        lgr.info("%d is disconnected" % (sock.fileno()))
                        call_hooks("modbus_tcp.TcpServer.on_disconnect", (self, sock))
                        sock.close()
                        self._sockets.remove(sock)
                        break                    
                    # handle all other sockets
                    sock.settimeout(5.0)
                    request = ""
                    is_ok = True
                    
                    #read the 7 bytes of the mbap
                    while (len(request) < 7) and is_ok: 
                        new_byte = sock.recv(1)
                        if len(new_byte) == 0:
                            is_ok = False    
                        else:
                            request += new_byte
                        
                    retval = call_hooks("modbus_tcp.TcpServer.after_recv", (self, sock, request))
                    if retval <> None:
                        request = retval
                    
                    if is_ok:
                        #read the rest of the request
                        length = self._get_request_length(request)
                        while (len(request) < (length + 6)) and is_ok:
                            new_byte = sock.recv(1)
                            if len(new_byte) == 0:
                                is_ok = False
                            else:
                                request += new_byte 
                    
                    if is_ok:
                        response = ""
                        #parse the request
                        try:
                            response = self.handle_b(request)       
                        except Exception, msg:
                            lgr.error("Error while handling a request, Exception occurred: %s", msg)
                        
                        #send back the response
                        if response:
                            try:
                                retval = call_hooks("modbus_tcp.TcpServer.before_send", (self, sock, response))
                                if retval <> None:              
                                    response = retval
                                sock.send(response)
                            except Exception, msg:
                                is_ok = False
                                lgr.error("Error while sending on socket %d, Exception occurred: %s", \
                                             sock.fileno(), msg)
            except Exception, excpt:
                lgr.warning("Error while processing data on socket %d: %s", sock.fileno(), excpt)
                call_hooks("modbus_tcp.TcpServer.on_error", (self, sock, excpt))
                sock.close()
                self._sockets.remove(sock)

class TcpMbap_b(modbus_tcp.TcpMbap):
    """
    Edit for fuzzer. 
    Defines the information added by the Modbus TCP layer
    """
    
    def __init__(self):
        """Constructor: initializes with 0"""

        self.transaction_id = 0
        self.protocol_id = 0
        self.length = 0
        self.unit_id = 0

    def pack(self):
        """convert the TCP mbap into a string"""
        return struct.pack(">HHHB", self.transaction_id, self.protocol_id, self.length, self.unit_id)
        
    def unpack(self, value):
        """extract the TCP mbap from a string"""
        (self.transaction_id, self.protocol_id, self.length, self.unit_id) = struct.unpack(">HHHB", value) 

    def check_length_b(self, pdu_length):
        """Check the length field is valid. If not raise an exception"""
        following_bytes_length = pdu_length+1
        if self.length != following_bytes_length:
            lgr.error ("Response length is %d while receiving %d bytes. " % (self.length, following_bytes_length))
            return "" 
        return ""        


    def check_response_b(self, request_mbap, response_pdu_length):
        """Check that the MBAP of the response is valid. If not write log error"""
        error_str = self._check_ids_b(request_mbap)
        if len(error_str)>0:
            lgr.error('ModbusInvalidMbapError %r.' % (error_str))    

    def _check_ids_b(self, request_mbap):
        """
        activates when I have only answers
        Check that the transaction in the request and the response are similar -if not returns a string describing the error
        self.length=length of response 
        fuzz_session.length_not_f is length of following_bytes_length request(actual length)
        request_mbap.length is fuzzing length
        request_mbap.length !=actual length or request_mbap.length >254 (MAX len packet Modbus/TCP, 260-6=254)
        fuzz_session.mbap_error=0 is flag for log error response 
        """
        error_str = ""

        if request_mbap.transaction_id != self.transaction_id:
            error_str += "Invalid transaction id: request=%d %s- response=%d  %s ," % \
                (request_mbap.transaction_id, hex(request_mbap.transaction_id), self.transaction_id, hex(self.transaction_id))
        
        if (request_mbap.protocol_id != self.protocol_id) or (request_mbap.protocol_id !=0):
            error_str += "Invalid protocol id  request=%d  %s- response=%d  %s ," % \
                (request_mbap.protocol_id, hex(request_mbap.protocol_id),self.protocol_id,hex(self.protocol_id))
        
        if (request_mbap.unit_id != self.unit_id ):
            error_str += "Invalid unit id request=%d  %s - response=%d  %s " % (request_mbap.unit_id, hex(request_mbap.unit_id),self.unit_id,hex(self.unit_id))
        
        if (request_mbap.length != fuzz_session.length_not_f) or (request_mbap.length == 0) or (request_mbap.length > 254):
            error_str += "Invalid length request=%d  %s - length of response =%d  %s " % (request_mbap.length, hex(request_mbap.length),self.length,hex(self.length))        

        if error_str == "" :
            fuzz_session.mbap_error=0
        else : fuzz_session.mbap_error=1    
        
        return error_str        


class TcpQuery_b(modbus.Query,modbus_tcp.TcpQuery):
    """Subclass of a Query. Adds the Modbus TCP specific part of the protocol"""    
    
    last_transaction_id = 0
    
    def __init__(self):
        """Constructor"""
        modbus.Query.__init__(self)

        self._request_mbap = TcpMbap_b()
        self._response_mbap = TcpMbap_b()

    def get_transaction_id_b(self):
        """returns an identifier for the query"""

        if TcpQuery_b.last_transaction_id < 0xffff:
            TcpQuery_b.last_transaction_id += 1
        else:
            TcpQuery_b.last_transaction_id = 0
        return TcpQuery_b.last_transaction_id
    
    
    def build_request_b(self,pdu,slave):
        """
        Add the Modbus TCP part to the request, process for fuzzer
        """
        adu=""
        p=process()
        #static variable for giving a unique id to each query
        #normal MBAP first self._request_mbap without fuzz testing
        self._request_mbap.transaction_id = self._get_transaction_id()
        self._request_mbap.length = len(pdu)+1
        self._request_mbap.protocol_id = 0 
        self._request_mbap.unit_id = slave
        # call the fuzzing mode and fuzzing
        adu,pdu=p.init_new_session(pdu,slave)            
        #attension !!!case  pdu len much as follow bytes e.g-('test_field_PDU', 3.0)
        #and TEST fc field constat as the original message
        if fuzz_session.priority==3 :
            self._request_mbap.length = len(pdu)+1
            fuzz_session.length_not_f= len(pdu)+1
        
        elif fuzz_session.priority==2 :
            #case 2 chech multiple ADU/TCP Seg,mbap.len is a)much as follow bytes or b) much as first ADU
            self._request_mbap.length = len(pdu)+1
            lgr.warn('The mbap.length much as follow bytes is : %d' % self._request_mbap.length)
        
        elif fuzz_session.priority==1 :
            #fuzz instanse mbap for  response_mbap.check_response_b 
            self._request_mbap.unpack(adu)
            fuzz_session.length_not_f= len(pdu)+1
            return adu+pdu
        else : 
            #case not fuzz testing--testing!!
            fuzz_session.length_not_f= len(pdu)+1
            pass    
                
        if self._request_mbap.length>65535 :
            self._request_mbap.length=65535

           
        if adu=="" :                                      #no fuzzing mbap
           mbap = self._request_mbap.pack()               #pack to string 
           return mbap+pdu                                #to return to modbus_b.py def executed
        else :
           self._request_mbap.unpack(adu)                 #fuzz instanse mbap /for response_mbap.check_response_b                                     # 
           return adu+pdu                                 # string fields return to modbus_b.py def executed    
    
    def parse_request_b(self, mbap,pdu):
        """
        Extract the pdu from a modbus request
        not use in this time

        """
        if len(mbap+pdu) > 6:    
            self._request_mbap.unpack(mbap)
            error_str = self._request_mbap.check_length_b(len(pdu))
            if len(error_str) > 0:
                lgr.error('ModbusInvalidMbapError %r.' % (error_str))
            return adu+pdu  
        else:
            error_str +="Request length is only %d bytes. " % (len(request))
            lgr.error('ModbusInvalidMbapError %r.' % (error_str))
            return adu+pdu 

    def parse_response_b(self, response):
        """ add for fuzzer and black box/reconnaissance
        Extract the pdu from the Modbus TCP response
        check mbap and write log/ for fuzzer dissect
        """

        if len(response) > 6:
            mbap, pdu = response[:7], response[7:]
            self._response_mbap.unpack(mbap)
            #error_str = self._request_mbap.check_length_b(len(pdu))
            self._response_mbap.check_response_b(self._request_mbap, len(pdu))  
            return pdu
        else:
            lgr.error('ModbusResponseError length is only %d bytes.' % len(response))
            return response

    def build_request_blackbox(self, pdu, slave):
        """ Add the Modbus TCP part to the request
        fuzz_session.length_not_f=len(pdu)+1, chech error  in def _check_ids_b
        """
        if (slave < 0) or (slave > 255):
            raise InvalidArgumentError, "%d Invalid value for slave id" % (slave)
        self._request_mbap.length = len(pdu)+1 ; fuzz_session.length_not_f=len(pdu)+1 
        self._request_mbap.transaction_id = self._get_transaction_id()
        self._request_mbap.unit_id = slave
        mbap = self._request_mbap.pack()
        return mbap+pdu        
    
    