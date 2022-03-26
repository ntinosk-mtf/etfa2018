
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
import logging.handlers as handlers
import fuzz_session
from utils_b import *
from defines import *
from  libraries.library_calc_value import *
from libraries.test_case import *
from utils_b import is_way,not_exist_field
from raise_except import (CsvError,TestfieldError) #exception for raise_except

logger = modbus_tk.utils.create_logger("console") # create logger- 
lgr=logging.getLogger('')

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
        self.t=65535
        self.dir='./Nist-csv'
        self.pathCSV=self.dir+"/MBAP_pair.csv"
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
   
    def MBAP_pairwice(self):
        """ 
        Pairwise  test for MBAP from ./Nist-csv
        read CSV file & load in list of list, convert all elements to init
        sort length field  
        ACTS Test Suite Generation
        Number of configurations: 22612
        mbap_transaction,mbap_protocol,mbap_len,mbap_slave
        0,0,1,1
        0,1,2,2
        0,2,3,3
                   ..
        """               
        
        try:
            if os.path.exists(self.pathCSV):            
                with open(self.pathCSV, 'r') as f:#Read MBAP CSV
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    pairwise = list([[int(x) for x in line] for line in pairwise_temp])
                    pairwise.sort(key = lambda row: row[2])         #sort length field        
            else:  raise CsvError ("CSV not exist")                  
                                                                   
        #except IOError, catch problem in csv file   
        except Exception  as er:         
            lgr.error("     > %s,IOError CSV ..send zero values ..",str(er));return np.zeros((1,4),int)
                                    
        #raise ValueError ('no data')
        if len(pairwise)==0:return np.zeros((1,4),int)
               
        return np.array(pairwise)
      
    def TransIdIs(self): #not use
        """
        The function increasing/decrasing the transaction id
        This function invalid transaction_id in the mbap
        """
        global flag_IDs       
        query = modbus_tcp_b.TcpQuery_b()
        last_transaction_id  = query.get_transaction_id_b()
        return random.randint(0,65535)
    
    def mbap_custom(self):       
        """ 2-way Combinatorial testing 
        Pairwise  test for MBAP from ./Nist-csv
        read CSV file 
        """
        
        global  slave,pairwice_MBAP       
        if  len(pairwice_MBAP)==0 :  pairwice_MBAP= self.MBAP_pairwice()             
        self.mbap.transaction_id =pairwice_MBAP[0][0]
        self.mbap.protocol_id = pairwice_MBAP[0][1]
        self.mbap.length = pairwice_MBAP[0][2]
        self.mbap.unit_id = pairwice_MBAP[0][3]
        pairwice_MBAP=np.delete(pairwice_MBAP, 0, 0);lgr.warn('     > Combinatorial NIST-ACTS, pairwise for MBAP, remain test: %d' % (len(pairwice_MBAP))) 
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
        lof=list_of_fuzz();  tcc=test_case_coverage() 
        function_code=int.from_bytes(pdu[0:1], byteorder='big')                  
        query = modbus_tcp_b.TcpQuery_b();mbap = modbus_tcp_b.TcpMbap_b() 
                                                                      
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_MBAP[:]
            is_way('Combinatorial') # from utils_b Choice single or pairwise test of fields
            
        test_field = fuzz_session.fields_of_list[0]      
        lgr.info('FC: %d ..0x%02X, testing MBAP Field % r ' % (function_code,function_code,test_field))
       
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
            not_exist_field(test_field)  #case not exist field  of test ,/in utils_b.py

        lgr.info('transaction id is:  % d , 0x%02X ..' % (mbap.transaction_id,mbap.transaction_id))
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

        #The value 0 is also accepted to communicate directly, the value 0xFF has to be used
        lgr.info('unitID is:  % d , 0x%02X ..' % (mbap.unit_id,mbap.unit_id))
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
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :self.reset() 
        
        if (len(pairwice_MBAP)==0 and test_field=='Combinatorial'):            
            
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field4_valid,fuzz_session.field4_invalid])
            tcc.test_case (function_code,test_field,fuzz_session.test_field_MBAP, np.array(fuzz_session.tmp_test_list))
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_MBAP,fuzz_session.tmp_list_of_case,self.t)
            fuzz_session.tmp_test_list=[] 
            #if fuzz_session.fields_of_list: 
            fuzz_session.fields_of_list.pop(0)              #removes the item /'2-way'
            self.reset()
                
        if len(fuzz_session.fields_of_list)==0:
           fuzz_session.flag_reguest=False                 #Stop reguest and fuzzer 
        
        return  struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )
