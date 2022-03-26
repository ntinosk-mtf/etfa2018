#!/usr/bin/env python
# -*- coding: utf-8 -*-

import os
import modbus_tk.utils 
import modbus_tcp_b 
import modbus_b 
import fuzz_session
import logging.handlers as handlers
from  libraries.library_calc_value import *
from  libraries.s_primitives import *
from libraries.test_case import *
from defines import * #define  function, exeption e.a
from add_method  import ByteToHex
from  libraries.fuzz_patterns import *

# This class fuzz testing  a field of PDU Modbus protocol
# PAIRWISE  test for FC 01 ,02 ,03 ,04 , address +quantity bount + 20   
# program to find all  pairs in both arrays whose  sum is equal to given value x 
from libraries.pairs_address import pairs_address_qua 

from ifuzzer import Read_CSv_FC #from config import load_file             
from raise_except import (CsvError,TestfieldError)  #exception for raise_except     

#--------------------------------------------------------------------------------------------------------------------------
#This class fuzzing send illegal packet format (as dumplicate ADU/PDU, Remove PDU, combination len.mbap and follow len PDU)
#--------------------------------------------------------------------------------------------------------------------------

class test_illegal_PDU (object):
    
    lof=list_of_fuzz(); output_values=[]
   
    def __init__(self,adu="",mbap="",pdu="",QC=[],QH=[],A_CO=[],A_DI=[],A_IR=[],A_HR=[],output_value=65536,lendiagnostics_tumple=None):
        '''
        pairs OF COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
        integer_boundaries for byte count REG: quantity_of_x_list)
        
        pairsfind=pairs_address_qua()-- PAIRWISE test 
        - ---------------------------    Set PAIRWISE test Initializes  for address vs quantity   ----------------------
        Test case Initializing for FC01 --------- : .. in pairwice_READ_COILS.size 
        Test case Initializing for FC02 --------- : .... 
        Test case Initializing for FC03 --------- : ....
        Test case Initializing for FC04 --------- : ....

        matrixArr1=np.empty((0,2), int);matrixArr=np.empty((0,2), int)

		fc 15, 16 value 
        test only "interest" value, max_num=65536
        self.add_integer_boundaries(0)
        self.add_integer_boundaries(self.max_num // 2)
        ....
        self.add_integer_boundaries(self.max_num)

        bountery of coils and register see Modbus spec 
        self.limcoil_do=..
        ..

        '''
        #Pairwise test for FC01-FC04 load from  ./csvtestformat
        self.dirtestformat="./csvtestformat"
        self.pair="/FC0%d_pair.csv"
        self.pathtestformat=self.dirtestformat+self.pair

        self.limcoil_do=1968
        self.limcoil_up=2000
        self.limreg_do=121
        self.limreg_up=125
        self.bountery=2

        lof=list_of_fuzz()
        self.QC=QC
        self.QH=QH
        self.A_CO=A_CO
        self.A_DI=A_DI
        self.A_IR=A_IR
        self.A_HR=A_HR

        self.QC=lof.list_quantity_for_cart_prod(self.limcoil_do,  self.limcoil_up, self.bountery)    	
        self.QH=lof.list_quantity_for_cart_prod(self.limreg_do,self.limreg_up, self.bountery)
        self.A_CO=lof.list_address_for_cart_prod(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS,self.bountery)
        self.A_DI=lof.list_address_for_cart_prod(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN,self.bountery)
        self.A_IR=lof.list_address_for_cart_prod(fuzz_session.MIN_IN_REG,fuzz_session.MAX_IN_REG,self.bountery)       
        self.A_HR=lof.list_address_for_cart_prod(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG,self.bountery)     
             
        self.mbap=mbap
        self.pdu=pdu
        self.adu=adu
        self.Mult_output_value=[]
        self.max_num =output_value
        self.lendiagnostics_tumple=lendiagnostics_tumple
       
        #library of static fuzz VALUE of length
        self.illegal_pdu_len=[]

        #len of ADU for FC=1,2,3,4,5,6 
        self.len_ADU=12

        #Set dumplicate ADU test Read, Write FC, diagnostics
        self._FC_dumplicate_ADU=[1,2,3,4,5,6,15,16,8] 

        #If we want to see the repeated values:self._FC_dumplicate_ADU
        #tmp_FCmergedlist=support FC (FCs)from Configuration Read from CSV  
        if not fuzz_session.FC_dumplicate_ADU:    	
            tmp_FCs=Read_CSv_FC()                                                               #load FCs from module ifuzzer.py 
            fuzz_session.FC_dumplicate_ADU=[i for i in tmp_FCs if i in self._FC_dumplicate_ADU] #filter and add Diagnostics=0x08
            if  Diagnostics not in fuzz_session.FC_dumplicate_ADU: fuzz_session.FC_dumplicate_ADU.append (Diagnostics)
        
        #load first/one time list of test illegal PDU length of char and dumplicate_number 
        #print in log FC_dumplicate_ADU (FCd) 
        if fuzz_session.flag_init_illegal_pdu_len==True :
            self.print_FCd()
            self.lendiagnostics_tumple=20
            self.int_reset_lst()
            fuzz_session.flag_init_illegal_pdu_len=False

        #interest values , -256 +-2 , 65535 -1 -2
        #[0, 1, 32767, 32768, 32769, 255, 256, 254, 65533, 65535, 65534,....-256]

        if len(self.output_values)==0:
            self.output_values.append (0);self.output_values.append (1)
            self.output_values.append ((self.max_num // 2)-1)     #32767
            self.output_values.append (self.max_num // 2)         #32768
            self.output_values.append ((self.max_num // 2)+1)     #32769
            self.output_values.append ((self.max_num // 256)-1)   #
            self.output_values.append (self.max_num // 256)       #256
            self.output_values.append ((self.max_num // 256)-2)   #254
            self.output_values.append (self.max_num -3)
            self.output_values.append (self.max_num -1)           #65535
            self.output_values.append (self.max_num -2)

            self.output_values.append (-(self.max_num // 256)+2)    #-258 
            self.output_values.append (-(self.max_num // 256)+1)    #-255
            self.output_values.append (-(self.max_num // 256))      #-256
            self.output_values.append (-(self.max_num // 256)-1)    #-257
            self.output_values.append (-(self.max_num // 256)-2)    #-258                 
    
    def int_reset_lst(self):
        """ 
        load list fuzz VALUE (interesting up to 256 and 512,512,1024,2048,4096) 
        of number Dumplicate send ADU and fuzz VALUE of length
        """ 

        fuzz_session.illegal_pdu_len=self.int_lof(self.illegal_pdu_len)  
        fuzz_session.dumplicate_number=self.list_of_dumpl_number()
        return None 

    def int_lendiagnostics_tumpl(self):
        """ The return len of  diagnostics_tumple with send on test FC=0X08 """             
        self.lendiagnostics_tumple=20
        return  None

    def print_FCd(self):
        """ print log FC_dumplicate_ADU (FCd)  """
             
        lgr.info('Test FCs in dumplicate ADU message : %s' %fuzz_session.FC_dumplicate_ADU) 
        return None    

    def last_FC_d(self):
        """ Check last FC_dumplicate_ADU""" 
        
        if len(fuzz_session.FC_dumplicate_ADU)==0 :
            if fuzz_session.test_format==0:
                fuzz_session.fp.insert(len(fuzz_session.fp)+1,fuzz_session.fp.pop(0)) #next fp: ['test_illegal_len_PDU']
            else:fuzz_session.flag_reguest=False
         
        
    def int_lof(self,illegal_pdu_len):
        """ The def implements library of static fuzz VALUE of length"""    
         
        illegal_pdu_len=list_of_fuzz().illegal_len_list()
        fuzz_session.illegal_pdu_len= illegal_pdu_len
        fuzz_session.len_of_list=len(illegal_pdu_len)
        return  illegal_pdu_len
            

    def list_of_dumpl_number(self):
        """ 
        The def implements library of static fuzz VALUE (interesting 1 ..128 .. 256 and 512,512,1024,2048,4096) 
        of number Dumplicate send ADU (not 0)
        """    
        list_of_du_notzero=list_of_fuzz().lib_interesting_256_exte()
        list_of_du_notzero.remove(0);  return list_of_du_notzero          
       
    def mbap_custom(self,pdu):
        """ create mbap OBJECT custom """
        
        query = modbus_tcp_b.TcpQuery_b() 
        mbap1 = modbus_tcp_b.TcpMbap_b()                      
        mbap1.transaction_id = query.get_transaction_id_b()
        mbap1.protocol_id = 0
        mbap1.length = len(pdu)+1
        mbap1.unit_id = 1 
        return mbap1      
    
    def load_file(self,function_code):
        """ 
        Pairwise test -create for FC01-FC04.. dir="./csvtestformat"
        """        
        pairwise=[]
        try:
            if os.path.exists(self.pathtestformat%function_code): #catch, if not file NIST-ACTS...
                # read CSV file & load into list               
                with open(self.pathtestformat%function_code,'r') as f:
                    reader = csv.reader(f); pairwise_temp = list(reader)                   
                    #convert all elements to Init
                    pairwise = np.array(list([[int(x) for x in line] for line in pairwise_temp]))
                    
            else: raise CsvError ("CSV not exist")
                                               
        #except IOError, catch problem in csv file 
        except  Exception  as er:  lgr.error("     > %s,IOError CSV ..send zero values ..",str(er));return np.zeros((1,2),int)   
               
        if len(pairwise)==0:
            lgr.warn("     > Csv file not data   ..return");return np.zeros((1,2),int)

        #load from csv test case for FC01-FC04      
        return np.array(pairwise)


    def mbap_zero(self,pdu):
        """ create mbap OBJECT custom zero all  """
        
        query = modbus_tcp_b.TcpQuery_b()
        mbap0 = modbus_tcp_b.TcpMbap_b()                             
        mbap0.transaction_id = 0
        mbap0.protocol_id = 0
        mbap0.length =0
        mbap0.unit_id = 0
        return mbap0 
   
    
    def fuzz_payload(self,pdu):
        '''
        This functions fuzzing a message Modbus, test_dumplicate_ADU, test_illegal_len_PDU (not spec), 
        remove PDU from packet/
        module --dict_operation_f_test.py
        in start fuzz_session.fp= 'fp': ['test_dumplicate_ADU','test_illegal_len_PDU'],'repeat PDU' --not use,
        if 'test_illegal_len_PDU' then
        key test 'attack_byte_PDU':['attack_randByte','attack_inter_byte', 'remove'],
        from console choise 0,1,2 ,(defaults) fo=0 all test
        
        '''    
        
        if fuzz_session.test_format==1:
        	fuzz_type = fuzz_session.fp[0]
        elif fuzz_session.test_format==2 :fuzz_type = fuzz_session.fp[1]
        else:fuzz_type = fuzz_session.fp[0] # first test 'test_dumplicate_ADU', (defaults) fo=0 all test

        lgr.info('Fuzzing a payload : ' + fuzz_type) 
       
        if fuzz_type=='test_dumplicate_ADU' :
            adu,pdu=self.fuzz_payload_func[fuzz_type](self,pdu)
                                                          
        elif fuzz_type=='test_illegal_len_PDU' :
            adu,pdu=self.fuzz_payload_func[fuzz_type](self,pdu)                             
           
        else :  
            lgr.error('error dict_operation/not fuzz_type'); fuzz_type="None"   
           
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
        adu = ""   string

       """
       adu = "";lgr.info('remove fields of data PDU, Datasize: %d' %((len(pdu))-1))      
       payloads_pdu = []
       if len(pdu)-1==fuzz_session.byte_remove or len(pdu)-1==0:
            #shift a list, next fuzz operation
            fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))  #shift a list, next fuzz 'attack_randByte]
            fuzz_session.byte_remove=0;fuzz_session.flag_reguest=False           
            fuzz_session.flag_test_attack_randByte=True # for next log, Fuzz testing format message: 'attack_randByte' in  ifuzzer.py 
     
            if fuzz_session.test_format==0:
                fuzz_session.fp.insert(len(fuzz_session.fp)+1,fuzz_session.fp.pop(0)) #next fp: [test_dumplicate_ADU]
                fuzz_session.flag_test_attack_randByte=False # not log, Fuzz testing format message: 'attack_randByte' in  ifuzzer.py
                fuzz_session.flag_test_dumplicate_ADU=False 

       fuzz_session.byte_remove +=1
       new_pdu=pdu[0:fuzz_session.byte_remove]  # i=1 start and i=4 e.g FC01 PDU 
       lgr.info('SendDatasize : %d' % len(new_pdu[1:])) 
       pdu=new_pdu
       return adu,pdu
    

    def test_illegal_len_PDU(self,pdu): 
       '''
       This function after legal PDU inserts a heuristic illegal length random or one char PDU and send 
       send after PDU, len of random string /ascii/all char/only alpanum/only one char
       fuzz_test_PDU= ['test_illegal_len_PDU','test_dumplicate_ADU','remove']--remove /replace
       attack_PDU=['attack_randByte','attack_inter_byte','remove'] 
       fuzz_session.fp= ['test_illegal_len_PDU','test_dumplicate_ADU',]--replace --fuzz_test_PDU
       if 'test_illegal_len_PDU' then 
       fuzz_session.attack_byte_PDU=['attack_randByte','attack_inter_byte','remove']    

       '''  
       r=0; length=0 ;adu= ""
       fuzz_test_PDU = fuzz_session.fp[0];attack_PDU= fuzz_session.attack_byte_PDU[0]
       lgr.info('Fuzz testing attack PDU: %r '%attack_PDU)
       function_code=int.from_bytes(pdu[0:1], byteorder='big')                                           
       #function_code, = struct.unpack(">B", pdu[0])                                           
       lgr.info('The function_code is: % r ' % function_code) 

       if function_code == Diagnostics :
           lgr.info('sub code is:  % r'% ByteToHex(pdu[1:3]))
           DiagAndsubcode = pdu[0:3] #; pdu=DiagAndsubcode                                                    
       else  : 
           pass                                  
                                    
       if attack_PDU =='attack_randByte' :
            pdu=self.test_attack_randByte(pdu)
       
       elif  attack_PDU =='attack_inter_byte' :
            pdu=self.test_attack_interByte(pdu)

       elif attack_PDU =='remove_byte_of_PDU' : 
            adu,pdu=self.fuzz_payload_func[attack_PDU](self,pdu)

       else  :lgr.info('not fuzz testing');pass

       if len(pdu)>253 or len(pdu)==0:
            lgr.warn('total len PDU request out of spec .. !! : %d bytes' % len(pdu))
       else :
            lgr.info('total len PDU request in of spec : %d bytes' % len(pdu))
            
       return adu,pdu

    def test_attack_randByte(self,pdu):
        '''
        This function after legal PDU inserts a heuristic illegal length random or one char PDU and send 
        send after PDU, len of random string /ascii/all char/only alpanum//only one char
        if fuzz_session.illegal_pdu_len list is last item ,  #shift a list, next fuzz 'attack_inter_byte
        pdu is string byte b""
        pdu = (''.join([chr(random.randint(0,255))  for _ in  range(attacksize)])) is string
        '''
        r=random.randint(0,100)
       
        attacksize=fuzz_session.illegal_pdu_len[fuzz_session.item_list]       
        fuzz_session.item_list += 1;lgr.info('attacksize: %d' % attacksize)
        
        if attacksize==fuzz_session.illegal_pdu_len[-1]:
            fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0)) #shift a list, next fuzz 'attack_inter_byte'
            fuzz_session.item_list=0;fuzz_session.flag_test_attack_inter_byte=True  #set flag to log change test Fuzz testing format in def change_test_format
                        
        if r<35:                                                                      
            lgr.info('all char')
            pdu += (''.join([chr(random.randint(0,255))  for _ in  range(attacksize)])).encode()
           
        elif r<70:                                         
            lgr.info('ascii only');pdu += (''.join([chr(random.randint(0,128)) for i in range(0,attacksize)])).encode()
            
        elif r<80:     
            lgr.info('only alpanummeric');pdu += (''.join([chr((random.randint(0,96))+32) for i in range(0,attacksize)])).encode() 
                                         
        else:                                             
            c=random.randint(0,96)+32
            lgr.info('patterns one char: %r , 0x%02X ' % (c,c))
            attackstring = (''.join( [chr(c) for i in range(0,attacksize)])).encode()
            pdu += attackstring       
        
        return pdu  


    def test_attack_interByte(self,pdu):
        '''
        This function after legal PDU inserts (attacksize) a heuristic illegal length intersting byte (FE,FF,00, exception ,...) in defines.py
        size  is value *  inter byte ,and attackstring[:65555] bountery +-10 
        fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))   
        index >>fuzz_session.item_list_hex, fuzz_session.item_list
        if  intersting byte >1 byte, adjucts in len  
        #test_class_of_msg= :['bad',  'diagnostics','exception','shell_code'], class of msg such exception ,bad e.g
        item_list=0;item_list_hex=0, tem list index for interesting byte   and class msg 

        l.insert(newindex, l.pop(oldindex))-last item from class msg e.g exception
        fuzz_session.class_of_msg.insert(len(fuzz_session.class_of_msg))+1,fuzz_session.class_of_msg.pop(0)) 

        '''
        lof=list_of_fuzz();msg_bytehex=b''
        if len(fuzz_session.class_of_msg) == 0:
            fuzz_session.class_of_msg=fuzz_session.test_class_of_msg[:]
        test_class_msg = fuzz_session.class_of_msg[0]                                   
        lgr.info('testing class of msg: % r ' % test_class_msg) #choice class of interesting msg

        if test_class_msg =="strings_format":
         
            if fuzz_session.item_list_hex <len(test_class_msg):  # <last item  (len ta)
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]#tumble object
            else: fuzz_session.item_list_hex =0   
                                       
        elif test_class_msg =="omission" :
       
            if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  (len ta)                
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]#tumble object 1
            else: fuzz_session.item_list_hex =0   
             
        elif test_class_msg =='diagnostics': 
           
            if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  (len ta)
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]#tuples object 1
            else: fuzz_session.item_list_hex =0   
          
        #'exception'
        elif test_class_msg =='exception': 
           
            if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]#tuples object 1
            else: fuzz_session.item_list_hex =0 
        
        elif test_class_msg =='bad': 
           
            if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  (len ta)
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]#tuples object 1
            else: fuzz_session.item_list_hex =0         
        
        elif test_class_msg =='sequence': 
            
            if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  (len ta)
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]
            else: fuzz_session.item_list_hex =0 

        elif test_class_msg =='serial': 
           
            if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  
                msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]
            else: fuzz_session.item_list_hex =0    
        
        else :
            lgr.warn('\t \t \t .....not in list   %s..' %test_class_msg)
            fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))    #Change testing , next "remove"                
        
        urlist_len=len(eval(test_class_msg))
        size=fuzz_session.illegal_pdu_len[fuzz_session.item_list]
        attackstring=fuzz_session.illegal_pdu_len[fuzz_session.item_list]*msg_bytehex
        #if  intersting byte >one (1) byte, adjucts in len  
        attackstring=attackstring[:fuzz_session.illegal_pdu_len[fuzz_session.item_list]]
        if len(attackstring)>65535:attackstring=attackstring[:65545] # bountery +-10

        lgr.info('size of: %s and test intersting bytes: %s ...%s ' % (size,ByteToHex(msg_bytehex),msg_bytehex)) 
        lgr.info('attacksize : %d' % len(attackstring));lgr.info('attackstring message first 260 Byte: %r' % ByteToHex(attackstring[:260]))
        
        if size==fuzz_session.illegal_pdu_len[-1]:
            fuzz_session.class_of_msg.pop(0) #del first item of class_of_msg.
            #reset item change class and list of len from item=0
            fuzz_session.item_list_hex=0;fuzz_session.item_list =0
            if size==fuzz_session.illegal_pdu_len[-1] and len(fuzz_session.class_of_msg)==0:
                fuzz_session.item_list=0;fuzz_session.item_list_hex=0
                # Change testing ...test remove           
                fuzz_session.attack_byte_PDU.append(fuzz_session.attack_byte_PDU.pop(0))  #shift a list, next fuzzing test 'remove']                
                fuzz_session.flag_test_formatremove=True 
        elif fuzz_session.item_list_hex ==urlist_len-1:
            #last  of test hexbyte of inter msg..class
            fuzz_session.item_list_hex=0
            fuzz_session.item_list += 1 
            
        else : fuzz_session.item_list_hex += 1 ;fuzz_session.item_list += 1  #place on the list msg class in test        
        pdu += attackstring;return pdu
           
    def send_dumplicate (self,pdu,pdu_next,item):
        '''
        IN THE END  SEND -RANDOM for all pairwice_address vs quantity (interesting)
        return self.adu,(pdu+dumplicate_message_zero+)
        return self.adu,(pdu+dumplicate_message)
        return self.adu,(pdu+dumplicate_message_zero+dumplicate_message+(dumplicate_message_zero+dumplicate_message)......)
        if len(dumplicate_message_zero_mbap)>65535:dumplicate_message_zero_mbap=dumplicate_message_zero_mbap[:65545] # bountery +-10 or 20
        same dumplicate_message

        '''
        mbap=self.mbap_custom(pdu_next)                                            
        mbap1= struct.pack(">HHHB", mbap.transaction_id, mbap.protocol_id, mbap.length, mbap.unit_id )          
        #mbap zero message
        mbap0=self.mbap_zero(pdu_next)
        mbap0= struct.pack(">HHHB", mbap0.transaction_id, mbap0.protocol_id, mbap0.length, mbap0.unit_id )
        r=random.randint(0,100)
                    
        if r<35:
            dumplicate_message_zero_mbap=(item*(mbap0+pdu_next))
            if len(dumplicate_message_zero_mbap)>65535:dumplicate_message_zero_mbap=dumplicate_message_zero_mbap[:65545]
            lgr.info('send  dumplicate_number %d,message_zero_mbap: %r ' % (item,ByteToHex(mbap0+pdu_next)))          
            return self.adu,(pdu+dumplicate_message_zero_mbap)
        elif r<70:         
            dumplicate_message=(item*(mbap1+pdu_next))
            if len(dumplicate_message)>65535:dumplicate_message=dumplicate_message[:65545]
            lgr.info('send  dumplicate_number %d,dumplicate_message: %r ' % (item,ByteToHex(mbap1+pdu_next)))           
            return   self.adu,(pdu+dumplicate_message)
        else: 
            dumplicate_message=(item*((mbap0+pdu_next)+(mbap1+pdu_next)))
            if len(dumplicate_message)>65535:dumplicate_message=dumplicate_message[:65545] 
            lgr.info('send  dumplicate_number %d,dumplicate_message_zero_mbap+dumplicate_message: %r ' % (item,ByteToHex((mbap0+pdu_next)+(mbap1+pdu_next))))            
            return self.adu,(pdu+dumplicate_message)    

    def test_dumplicate_ADU(self,pdu):
        '''
        This function inserts one or more dumplecate ADU in message Modbus and send
        Dumplicate test Read and Write FC 
        for self.FC_dumplicate_ADU=[1,2,3,4,5,6,15,16,8] if support
        self.QC=num quantity_of_x_list for coils

        pairwice_READ_COILS=np.array([], dtype=np.int16)..
        dumplicate_message: with interesting address vs quantity
        dumplicate_message_zero=mbap0+pdu_next
        fuzz_session.dumplicate_number, value message in ADU
        fuzz_session.item_list,  index in list of dumpl send
        fuzz_session.item_list_hex, index in list of hex (tuble)
         
        '''
        global slave,pairwice_WRITE_SINGLE_REGISTER,pairwice_READ_COILS,pairwice_READ_INPUT_REGISTERS,pairwice_READ_HOLDING_REGISTERS,pairwice_READ_DISCRETE_INPUTS,pairwice_WRITE_SINGLE_COIL                                     
        #extract function_code from support fc    
        function_code=int.from_bytes(pdu[0:1], byteorder='big')                                               
        lgr.info('The function_code is: % d'  % function_code)
        
        while True:
           
            #Case READ COILS as next Multiple Modbus messages (ADU)
            if  READ_COILS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 01: READ_COILS as next PDU')
                #Set PAIRWISE test Initializes 
                if  pairwice_READ_COILS.size==0:
                    pairwice_READ_COILS=self.load_file(READ_COILS)   # read from file
                    
                fuzz_session.starting_address=pairwice_READ_COILS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_COILS[0][1]
                pdu_next= struct.pack(">BHH", READ_COILS, fuzz_session.starting_address, fuzz_session.quantity_of_x)
                
                lgr.info('Coils address: %d ..0x%02X and quantity %d . 0x%02X ' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))                 
                item=fuzz_session.dumplicate_number[0]

                # del line of np table and rotate list of dumplicate
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)
                #next FC_dumplicate_ADU 
                if pairwice_READ_COILS.size==0:
                    fuzz_session.FC_dumplicate_ADU.remove(READ_COILS)
                    self.last_FC_d()  #Check last FC_dumplicate_ADU                                     
                return self.send_dumplicate (pdu,pdu_next,item)       
        
            elif READ_DISCRETE_INPUTS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 02: READ_DISCRETE_INPUTS as next PDU')
                
                if pairwice_READ_DISCRETE_INPUTS.size==0:
                    pairwice_READ_DISCRETE_INPUTS=self.load_file(READ_DISCRETE_INPUTS)
                                                
                fuzz_session.starting_address=pairwice_READ_DISCRETE_INPUTS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_DISCRETE_INPUTS[0][1]
                pdu_next= struct.pack(">BHH", READ_DISCRETE_INPUTS, fuzz_session.starting_address, fuzz_session.quantity_of_x)

                lgr.info('DISCRETE_INPUTS address : %d ..0x%02X and  quantity: %d..0x%02X .' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))                                
                item=fuzz_session.dumplicate_number[0]
                # del line of np table and rotete list of dumplicate
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_DISCRETE_INPUTS=np.delete(pairwice_READ_DISCRETE_INPUTS, 0, 0)
                #next FC_dumplicate_ADU
                if pairwice_READ_DISCRETE_INPUTS.size==0:
                    fuzz_session.FC_dumplicate_ADU.remove(READ_DISCRETE_INPUTS)
                    # FC 02: READ_DISCRETE_INPUTS as next PDU-Done
                    self.last_FC_d()    #Check last FC_dumplicate_ADU                 
                return self.send_dumplicate (pdu,pdu_next,item)  
         
            elif READ_HOLDING_REGISTERS  in  fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 03: READ_HOLDING_REGISTERS as next PDU')
                
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                    pairwice_READ_HOLDING_REGISTERS=self.load_file(READ_HOLDING_REGISTERS ) 
                    if len(pairwice_READ_HOLDING_REGISTERS)==0 :pairwice_READ_HOLDING_REGISTERS=np.zeros((1,2),int) #[[0,0]] #return   0,0, np.zeros((2,1) one test and next FC                 

                fuzz_session.starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                pdu_next= struct.pack(">BHH", READ_HOLDING_REGISTERS, fuzz_session.starting_address, fuzz_session.quantity_of_x)                 
                lgr.info('READ_HOLDING_REGISTERS address: %d ..0x%02X and quantity: %d ..0x%02X' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))               
                item=fuzz_session.dumplicate_number[0]
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                               
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                    fuzz_session.FC_dumplicate_ADU.remove(READ_HOLDING_REGISTERS)
                    self.last_FC_d()  #Check last FC_dumplicate_ADU 
               
                return self.send_dumplicate (pdu,pdu_next,item)                               
                   
            elif READ_INPUT_REGISTERS in fuzz_session.FC_dumplicate_ADU  :
                lgr.info('FC 04: READ_INPUT_REGISTERS as next PDU')
                if pairwice_READ_INPUT_REGISTERS.size==0:
                    pairwice_READ_INPUT_REGISTERS=self.load_file(READ_INPUT_REGISTERS)
                
                fuzz_session.starting_address=pairwice_READ_INPUT_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_INPUT_REGISTERS[0][1]
                pdu_next= struct.pack(">BHH", READ_INPUT_REGISTERS, fuzz_session.starting_address, fuzz_session.quantity_of_x)
                lgr.info('READ_INPUT_REGISTERS address: %d .0x%02X quantity: %d..0x%02X..' %(fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                 
                item=fuzz_session.dumplicate_number[0]

                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_INPUT_REGISTERS=np.delete(pairwice_READ_INPUT_REGISTERS, 0, 0)
               
                if pairwice_READ_INPUT_REGISTERS.size==0:
                	fuzz_session.FC_dumplicate_ADU.remove(READ_INPUT_REGISTERS)
                	self.last_FC_d() #Check last FC_dumplicate_ADU
               
                return self.send_dumplicate (pdu,pdu_next,item)

            elif WRITE_SINGLE_COIL in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 05: WRITE_SINGLE_COIL as next PDU')
                
                if pairwice_WRITE_SINGLE_COIL.size==0:                   
                    pairwice_WRITE_SINGLE_COIL=np.array(self.A_CO)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number() 
               
                starting_address=pairwice_WRITE_SINGLE_COIL[0]
                value=int(0xff00)                                            #int 65280              
                fuzz_session.starting_address=starting_address; fuzz_session.value=int(0x0001)
                pdu_next= struct.pack(">BHH", WRITE_SINGLE_COIL, fuzz_session.starting_address,int(0xff00))
                lgr.info('Coils address: %d .0x%02X  write value:%r  ' % (starting_address,starting_address,value))
                
                item=fuzz_session.dumplicate_number[0]
                # del line of np table and rotete list of dumplicate
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_WRITE_SINGLE_COIL=np.delete(pairwice_WRITE_SINGLE_COIL, 0, 0)# del line of np table
               
                if pairwice_WRITE_SINGLE_COIL.size==0:
                	fuzz_session.FC_dumplicate_ADU.remove(WRITE_SINGLE_COIL)
                	self.last_FC_d()   #Check last FC_dumplicate_ADU
                return self.send_dumplicate (pdu,pdu_next,item)  
               
            elif WRITE_SINGLE_REGISTER in fuzz_session.FC_dumplicate_ADU  :
                lgr.info('FC 06: WRITE_SINGLE_REGISTER as next PDU')
                if pairwice_WRITE_SINGLE_REGISTER.size==0:
                    #list of coils only not pairwice
                    pairwice_WRITE_SINGLE_REGISTER=np.array(self.A_HR)
                    fuzz_session.dumplicate_number=self.list_of_dumpl_number()  
                
                fuzz_session.starting_address=pairwice_WRITE_SINGLE_REGISTER[0];fuzz_session.value=int(0x0001)
                pdu_next= struct.pack(">BHH", WRITE_SINGLE_REGISTER,fuzz_session.starting_address,int(0x0001))                                                           
                lgr.info('address valid: %d .0x%02X write value:%r ' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.value))                                                                                            
                item=fuzz_session.dumplicate_number[0]

                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_WRITE_SINGLE_REGISTER=np.delete(pairwice_WRITE_SINGLE_REGISTER, 0, 0)# del line of np table
               
                if pairwice_WRITE_SINGLE_REGISTER.size==0:
                	fuzz_session.FC_dumplicate_ADU.remove(WRITE_SINGLE_REGISTER)
                	#FC 06: READ_INPUT_REGISTERS as next PDU-Done')
                	self.last_FC_d()                                         #Check last FC_dumplicate_ADU  
               
                return self.send_dumplicate (pdu,pdu_next,item)  
                       
            elif WRITE_MULTIPLE_COILS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 15: WRITE_MULTIPLE_COILS as next PDU')
                
                if  pairwice_READ_COILS.size==0 :
                	pairwice_READ_COILS=self.load_file(READ_COILS)
                          
                fuzz_session.starting_address=pairwice_READ_COILS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_COILS[0][1]
                if fuzz_session.quantity_of_x>1968:self.Mult_output_value=(1968//8)*[self.output_values[0]]
                    
                else :self.Mult_output_value=(fuzz_session.quantity_of_x//8)*[self.output_values[0]]
                byte_count= len(self.Mult_output_value) //2             
                
                if byte_count>255:byte_count =255

                lgr.info('starting address: %d .0x%02X , quantity_of_x: %d .0x%02X ' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                lgr.info('byte_count: %d .0x%02X ' % (byte_count,byte_count)); lgr.info('"interest" value: 0x%02X '%(self.output_values[0]))
                pdu_next = struct.pack(">BHHB", WRITE_MULTIPLE_COILS , fuzz_session.starting_address, fuzz_session.quantity_of_x,byte_count)
                
                for j in self.Mult_output_value : 
                    if 0<=self.Mult_output_value[0]<=255:
                        pdu_next +=struct.pack(">B",j)
                    else:
	                    fmt="H" if j>=0 else "h"
	                    pdu_next +=struct.pack(">" + fmt,j)

                item=fuzz_session.dumplicate_number[0]
                self.output_values.append(self.output_values.pop(0)) #next "interest" value 
                               
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)# del line of np table
                
                if pairwice_READ_COILS.size==0:
                	fuzz_session.FC_dumplicate_ADU.remove(WRITE_MULTIPLE_COILS)
                	#FC 15: READ_INPUT_REGISTERS as next PDU-Done'
                	self.last_FC_d()   #Check last FC_dumplicate_ADU
                	
                return self.send_dumplicate (pdu,pdu_next,item)

            elif WRITE_MULTIPLE_REGISTERS in fuzz_session.FC_dumplicate_ADU :
                lgr.info('FC 16: WRITE_MULTIPLE_REGISTERS as next PDU')
                    
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                    pairwice_READ_HOLDING_REGISTERS=self.load_file(READ_HOLDING_REGISTERS) 
            
                fuzz_session.starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]

                #output value, packet in spec-test only "interest" value ( -256 +-2 , 65535 -1 -2)
                if fuzz_session.quantity_of_x>121:self.Mult_output_value=123*[self.output_values[0]]             
                else :self.Mult_output_value=fuzz_session.quantity_of_x*[self.output_values[0]]
                byte_count = 2 * len(self.Mult_output_value)
                if byte_count>255:byte_count =255               
                pdu_next = struct.pack(">BHHB", WRITE_MULTIPLE_REGISTERS, fuzz_session.starting_address, fuzz_session.quantity_of_x,byte_count)

                for j in  self.Mult_output_value:
                      fmt="H" if j>=0 else "h"
                      pdu_next +=struct.pack(">" + fmt,j)

                lgr.info('starting address: %d .0x%02X quantity_of_x: %d .0x%02X' % (fuzz_session.starting_address,fuzz_session.starting_address,fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                lgr.info('byte_count: %d ..0x%02X'  % (byte_count,byte_count)); lgr.info('"interest" value: 0x%02X '%(self.output_values[0]))               
                item=fuzz_session.dumplicate_number[0]
                self.output_values.append(self.output_values.pop(0)) #next "interest" value 
                # del line of np table and rotete list of dumplicate
                fuzz_session.dumplicate_number.insert(len(fuzz_session.dumplicate_number)+1,fuzz_session.dumplicate_number.pop(0)) 
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                
                if pairwice_READ_HOLDING_REGISTERS.size==0:
                	fuzz_session.FC_dumplicate_ADU.remove(WRITE_MULTIPLE_REGISTERS)
                	#FC 16: READ_INPUT_REGISTERS as next PDU-Done')
                	self.last_FC_d()                                         #Check last FC_dumplicate_ADU
                return self.send_dumplicate (pdu,pdu_next,item)

            elif Diagnostics in fuzz_session.FC_dumplicate_ADU : 
                lgr.info('FC 8: Diagnostics as next PDU');test_class_msg='diagnostics' ;self.int_reset_lst()

                if fuzz_session.item_list_hex <len(eval(test_class_msg)):  # <last item  (len ta)
                   msg_bytehex=eval(test_class_msg)[fuzz_session.item_list_hex][1]#tuble object 1
                else: fuzz_session.item_list_hex =0 
                #define parameter len  
                urlist_len=len(eval(test_class_msg))
                size=fuzz_session.dumplicate_number[fuzz_session.item_list]
                pdu_next = msg_bytehex
                item=fuzz_session.dumplicate_number[fuzz_session.item_list]               
                lgr.info('test diagnostics bytes : %s ...%s ' % (ByteToHex(msg_bytehex),msg_bytehex))
                               
                if size==fuzz_session.dumplicate_number[-1] and  fuzz_session.item_list_hex ==urlist_len-1  :
                    fuzz_session.FC_dumplicate_ADU.remove(Diagnostics)
                    fuzz_session.item_list=0;fuzz_session.item_list_hex=0
                    self.last_FC_d()   #Check last FC_dumplicate_ADU
                        
                elif fuzz_session.item_list_hex ==urlist_len-1:
                    #last item of class  diagnostics..,next len
                    fuzz_session.item_list_hex=0;fuzz_session.item_list += 1 
                else : fuzz_session.item_list_hex += 1   #next byte hex only               
                return self.send_dumplicate (pdu,pdu_next,item) 
            else:
                lgr.info('Error/not support/Empty/FC list dumplicate ADU  : %s' %fuzz_session.FC_dumplicate_ADU)
                return  self.adu,pdu 
        return self.adu,pdu          

   
    # A map from payload fuzz type to payload fuzz function
    fuzz_payload_func = {}
    fuzz_payload_func['test_dumplicate_ADU'] = test_dumplicate_ADU     #dumple ADU(mbap+PDU) in the MESSAGE -
    fuzz_payload_func['remove_byte_of_PDU'] = payload_remove           #removes a payload pdu from the packet-
    #fuzz_payload_func['test_dumplicate_PDU'] = payload_message        #Fuzzig a dumple pdu /not implementation, next version
    fuzz_payload_func['test_illegal_len_PDU'] = test_illegal_len_PDU   #insert random or interesting byte after PDU 

