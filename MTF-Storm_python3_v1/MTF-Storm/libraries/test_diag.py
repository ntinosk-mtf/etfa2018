#!/usr/bin/env python
import sys
import struct
from diag import *
import modbus_b 
import modbus_tcp_b 
from utils_b import *
fuzz_request=5
Diagnostics=8

class test_diagnostics():
    '''
    This is the test for the pymodbus.diag_message module for Diagnostics FC /not use 
    '''
    
    '''  demo Diagnostics FC This is the test for the pymodbus.diag_message module for Diagnostics FC

                                                       data  field                    request
    '''
    diagnostics= [       
        
        (ReturnQueryDataRequest,                        '\x08\x00\x00\x00\x00')
        (RestartCommunicationsOptionRequest,            '\x00\x00'),                    #'\x08\x00\x01\x00\x00'
        #restartCommunaications/clear                                                   #\x08\x00\x01\xff\x00'),            
        (ReturnDiagnosticRegisterRequest,               '\x00\x00'),                    #'\x08\x00\x02\x00\x00'),
        (ChangeAsciiInputDelimiterRequest,              '\x00\x00'),                    #'\x08\x00\x03\x00\x00'),
        (ForceListenOnlyModeRequest,                    '\x00\x00'),                    #'\x08\x00\x04'),
        (ClearCountersRequest,                          '\x00\x00)'),                   #'\x08\x00\x0a\x00\x00')
        (ReturnBusMessageCountRequest,                  '\x00\x00)'),                   #'\x08\x00\x0b\x00\x00'
        (ReturnBusCommunicationErrorCountRequest,       '\x00\x00)'),                   #'\x08\x00\x0c\x00\x00'
        (ReturnBusExceptionErrorCountRequest,           '\x00\x00'),                    #'\x08\x00\x0d\x00\x00'
        (ReturnSlaveMessageCountRequest,                '\x00\x00'),                    #'\x08\x00\x0e\x00\x00'
        (ReturnSlaveNoResponseCountRequest,             '\x00\x00'),                    #\x08\x00\x0f\x00\x00
        (ReturnSlaveNAKCountRequest,                    '\x00\x00'),                    #'\x08\x00\x10\x00\x00'
        (ReturnSlaveBusyCountRequest,                   '\x00\x00'),                    #'\x08\x00\x11\x00\x00'
        (ReturnSlaveBusCharacterOverrunCountRequest,    '\x00\x00'),                    #'\x08\x00\x12\x00\x00'
        (ReturnIopOverrunCountRequest,                  '\x00\x00'),                    #'\x08\x00\x13\x00\x00'
        (ClearOverrunCountRequest,                      '\x00\x00'),                    #'\x08\x00\x14\x00\x00')
        (GetClearModbusPlusRequest,                     '\x00\x00'),                     #'\x08\x00\x15\x00\x03' GetClearModbusPlus/(Get Statistics)  
    ]                                                                                    #'\x08\x00\x15\x00\x04' GetClearModbusPlus/((Clear Statistics)) 

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

        """print  results_..""" 

          print >>sys.stderr, '                                                                              '
          for name, value in kwargs.items():
            print '{0} = {1}'.format(name, value)
          print >>sys.stderr, '                                                                              '    
          return       

    
    def reconise_dia(self):  
        """Looking for some  diagnostics for reconiss  """

        print '\n  send  diagnostics..'
        lgr.info('\n \t \t \t ........send  diagnostics..')    
        for msg, enc in self.diagnostics:
            response_pdu=master1.execute_master(slave,enc)
            
            print 'response_pdu : %r"' % ByteToHex(response_pdu)
            lgr.info('response pdu : ----->%r ' % ByteToHex(response_pdu))         
        
        return 

    def getSupportedsubcodesDiagnostics(self):                     

        supportedsubDiagnostics = []
        print "Looking for supported diagnostics subcodes.."
        for i in range(21,65535):      
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
                print "Function Code "+str(i)+" not supported."
                
              else:
                supportedDiagnostics.append(i)
                print "SubDiagnostics Code "+str(i)+" is supported."
          else:
            print "SubDiagnostics Code "+str(i)+" probably supported."
            supportedSubDiagnostics.append(i)

        print >>sys.stderr, '\n----------------supported sub Diagnostics  --------------'
        self.print_results(response=supportedsubDiagnostics)
        return        

        
    #---------------------------------------------------- Serial FC -----------------------------------------------#
     
    """      07 (0x07) Read Exception Status (Serial Line only) .
    #This function code is used to read the contents of eight Exception Status outputs in a remote device.  The function provides a simple method for
    #accessing this information, because the Exception Output references are known (no output reference is needed in the function).
         
    """
    def test_ReadExceptionStatus(self):
        for a in range(fuzz_request):
             handle  = ReadExceptionStatusRequest()            
             result = struct.pack(">B",Read_Exception_Status)+handle.encode()
             response=master1.execute_fpdu(slave,result) 
             lgr.info('answer >>  Output data: %s'  % (response,))
             print >>sys.stderr, 'Output data: %s' % (response,)
    
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
         for a in range(fuzz_request):

             handle  = GetCommEventCounterRequest()           
             result = struct.pack(">B",Get_Comm_Event_Counter)+handle.encode()
             response=master1.execute_fpdu(slave,result)
             print >>sys.stderr, 'response %r' % (response,) 
             lgr.info('Answer >>  response %s'  % (response, ))

          
    #""" 12 (0x0C) Get Comm Event Log (Serial Line only)    
    #This function code is used to get a status word, event count, message count, and a field of event bytes from the remote device.
    #The status word and event counts are identical to that returned by the Get Communications
    #Event Counter function (11, 0B hex). The message counter contains the quantity of messages processed by the remote device
    #since its last restart, clear counters operation, or power–up. This count is identical to that
    #returned by the Diagnostic function (code 08), sub-function Return Bus Message Count (code 11, 0B hex).
    #The event bytes field contains 0-64 bytes, with each byte corresponding to the status of one
    #MODBUS send or receive operation for the remote device. The remote device enters the events into the field in chronological order. Byte 0 is the most recent event. Each new byte
    #flushes the oldest byte from the field.
    #"""
    def test_GetCommEventLog(self):
        for a in range(fuzz_request):
            handle  = GetCommEventLogRequest()
            result = struct.pack(">B",Get_Comm_Event_Logs)+handle.encode()
            response=master1.execute_fpdu(slave,result)
            print >>sys.stderr, 'response %r' % (response,) 
            lgr.info('Answer >>  response %s'  % (response, ))
    
    #""" 17 (0x11) Report Server ID (Serial Line only) 
    #This function code is used to read the description of the type, the current status, and other information specific to a remote device.
    #"""
    def test_ReportSlaveId(self):
        for a in range(fuzz_request):
            handle = ReportSlaveIdRequest()
            result = struct.pack(">B",Report_Slave_Id)+handle.encode()
            response=master1.execute_fpdu(slave,result)
            print >>sys.stderr, 'response %r' % (response,) 
            lgr.info('Answer >>  response %s'  % (response, ))
    
    #This is the test for the pymodbus.diag_message module for Diagnostics FC
    #Testing diagnostic request messages for all sub_function_code '''
    def add_num(self,number):
        if fuzz_session.num_diagnostics_request==0:
        
            number=fuzz_session.num_diagnostics_request+8
            fuzz_session.num_diagnostics_request =number
            return 0

        number=fuzz_session.num_diagnostics_request+8   
        fuzz_session.num_diagnostics_request =number
      
        if fuzz_session.num_diagnostics_request==65535:
            fuzz_session.num_diagnostics_request=0  

        return number   


    def test_DiagnosticRequests(self):
        
        for msg,enc in self.diagnostics :
            
            # Diagnostic Sub Code 00
        
            if msg==ReturnQueryDataRequest:
                print >>sys.stderr, 'Fuzzing  FC 08- ReturnQueryDataRequest   ....'
                lgr.info('\t Fuzzing  FC 08-00 : ReturnQueryDataRequest  .... ')
                for a in range(fuzz_request):
                    
                    handle  = ReturnQueryDataRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    print ByteToHex(result)
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0                                     #reset counter num_diagnostics_request
            
            # Diagnostic Sub Code 01
            if msg==RestartCommunicationsOptionRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-01 RestartCommunicationsOptionRequest   ....'
                lgr.info('\t Fuzzing  FC 08-01 : RestartCommunicationsOptionRequest  .... ')
                for a in range(fuzz_request):
                    handle  = RestartCommunicationsOptionRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %s'  % (response, ))
                fuzz_session.num_diagnostics_request =0     
            
            # Diagnostic Sub Code 02
            if msg==ReturnDiagnosticRegisterResponse:
                print >>sys.stderr, 'Fuzzing  FC 08-02 ReturnDiagnosticRegisterRequest  ....'
                lgr.info('\t Fuzzing  FC 08-02 : ReturnDiagnosticRegisterRequest  .... ')
                for a in range(fuzz_request):
                    handle  = ReturnDiagnosticRegisterRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))
                
                fuzz_session.num_diagnostics_request =0 
            
            # Diagnostic Sub Code 03
            if msg==ChangeAsciiInputDelimiterRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-03  ChangeAsciiInputDelimiterRequest ....'
                lgr.info('\t Fuzzing  FC 08-03 : ChangeAsciiInputDelimiterRequest  .... ')
                for a in range(fuzz_request):
                    handle  = ChangeAsciiInputDelimiterRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0     
            
            # Diagnostic Sub Code 04
            if msg==ForceListenOnlyModeRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-04  ForceListenOnlyModeRequest ....'
                lgr.info('\t Fuzzing  FC 08-04 : ForceListenOnlyModeRequest  .... ')
                for a in range(fuzz_request):
                    handle  = ForceListenOnlyModeRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0 


            # Diagnostic Sub Code 10
            if msg==ForceListenOnlyModeRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-10  ClearCountersRequest ....'
                lgr.info('\t Fuzzing  FC 08-04 : ClearCountersRequest  .... ')
                for a in range(fuzz_request):
                    handle  = ClearCountersRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0              

            # Diagnostic Sub Code 11
            if msg==ReturnBusMessageCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-11  ReturnBusMessageCountRequest,....'
                lgr.info('\t Fuzzing  FC 08-11 : ReturnBusMessageCountRequest  .... ')
                for a in range(fuzz_request):
                    handle  = ReturnBusMessageCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0     

            # Diagnostic Sub Code 12
            if msg==ReturnBusCommunicationErrorCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-12  ReturnBusCommunicationErrorCountRequest....'
                lgr.info('\t Fuzzing  FC 08-12 : ReturnBusCommunicationErrorCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnBusCommunicationErrorCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0         

            # Diagnostic Sub Code 13
            if msg==ReturnBusExceptionErrorCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-13  ReturnBusExceptionErrorCountRequest....'
                lgr.info('\t Fuzzing  FC 08-13 : ReturnBusExceptionErrorCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnBusExceptionErrorCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0     

            # Diagnostic Sub Code 14
            if msg==ReturnSlaveMessageCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-14  ReturnSlaveMessageCountRequest....'
                lgr.info('\t Fuzzing  FC 08-14 : ReturnSlaveMessageCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnSlaveMessageCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0     

            # Diagnostic Sub Code 15
            if msg==ReturnSlaveNoResponseCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-15  ReturnSlaveNoResponseCountRequest....'
                lgr.info('\t Fuzzing  FC 08-15 : ReturnSlaveNoResponseCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnSlaveNoResponseCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0     


            # Diagnostic Sub Code 16
            if msg==ReturnSlaveNAKCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-16  ReturnSlaveNAKCountRequest....'
                lgr.info('\t Fuzzing  FC 08-16 : ReturnSlaveNAKCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnSlaveNAKCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0         

            # Diagnostic Sub Code 17
            if msg==ReturnSlaveBusyCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-17  ReturnSlaveBusyCountRequest....'
                lgr.info('\t Fuzzing  FC 08-17 : ReturnSlaveBusyCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnSlaveNAKCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0 


            # Diagnostic Sub Code 18
            if msg==ReturnSlaveBusCharacterOverrunCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-18  ReturnSlaveBusCharacterOverrunCountRequest....'
                lgr.info('\t Fuzzing  FC 08-18 : ReturnSlaveBusCharacterOverrunCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnSlaveBusCharacterOverrunCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0             

            # Diagnostic Sub Code 19
            if msg==ReturnIopOverrunCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-19  ReturnIopOverrunCountRequest....'
                lgr.info('\t Fuzzing  FC 08-19 : ReturnIopOverrunCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ReturnIopOverrunCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0         

            # Diagnostic Sub Code 20
            if msg==ClearOverrunCountRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-20  ClearOverrunCountRequest....'
                lgr.info('\t Fuzzing  FC 08-20 : ClearOverrunCountRequest .... ')
                for a in range(fuzz_request):
                    handle  = ClearOverrunCountRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0 

            # Diagnostic Sub Code 21                                sub_function_code = 0x0015
            #'\x08\x00\x15\x00\x03'),                               #GetClearModbusPlus/(Get Statistics)     
            #\x08\x00\x15\x00\x04'),                                #GetClearModbusPlus/((Clear Statistics)) 
            if msg==GetClearModbusPlusRequest:
                print >>sys.stderr, 'Fuzzing  FC 08-21  GetClearModbusPlusRequest....'
                lgr.info('\t Fuzzing  FC 08-21 : GetClearModbusPlusRequest .... ')
                for a in range(fuzz_request):
                    handle  = GetClearModbusPlusRequest(self.add_num(fuzz_session.num_diagnostics_request))
                    result = struct.pack(">B",Diagnostics)+handle.encode()
                    response=master1.execute_fpdu(slave,result)
                    print >>sys.stderr, 'response %r' % (response,) 
                    lgr.info('Answer >>  response %r'  % (response, ))

                fuzz_session.num_diagnostics_request =0         
 
# Main
if __name__ == "__main__":
    main()