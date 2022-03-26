#!/usr/bin/env python
# -*- coding: utf-8 -*-

import itertools
import logging.handlers as handlers
import modbus_tcp_b 
import modbus_b
import fuzz_session 

from utils_b import is_way,not_exist_field
from  libraries.library_calc_value import *
from  libraries.s_primitives import *
from libraries.test_case import *
from defines import *  #define  function, add method e.a
from add_method  import ByteToHex

# program to find all  pairs in both arrays whose  sum is equal to given value x 
# This class fuzz testing  a field of PDU Modbus protocol
# PAIRWISE  test for FC 01 ,02 ,03 ,04 , address +quantity bount + 20   
# program to find all  pairs in both arrays whose  sum is equal to given value x
from libraries.pairs_address import pairs_address_qua 

from raise_except import (CsvError,TestfieldError)  #exception for raise_except    
from allpairspy import AllPairs  #Use allpairspy, https://github.com/thombashi/allpairspy

class fuzzer_pdu(object):    
    
    output_values=[]

    def __init__(self, output_value=65536): 
        
        """
        Constructor. Set the Initializing settings
        public_codes={1-64, 73-99, 111-127},User_defined codes=ranges {65-72, 100-110}
        exeption_codes interesting value 128_to_255
        self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
        fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))           #shift a list
        test only "interest" value, max_num=65536
        self.add_integer_boundaries(0)
        self.add_integer_boundaries(self.max_num // 2)
        ....
        self.add_integer_boundaries(self.max_num)

        """ 
        lof=list_of_fuzz() 
        self.public_codes=[i for j in (list(range(0,65)), list(range(72,100)),range(110,128)) for i in j]
        self.User_defined_codes=[i for j in ((list(range(64,73)), list(range(99,111)))) for i in j]
        self.exeption_codes=lof.lib_interesting_128_to_255()

        #Pairwise test FC15, FC16, FC23, FC43 ..
        self.dir='./Nist-csv'
        self.pathCSV=self.dir+"/FC%d_pair.csv"

        #Pairwise test for FC01-FC04 load from  ./csvtestPDU,  as csv-defaults
        self.dirtestPDU="./csvtestPDU"
        self.pair="/FC0%d_pair.csv" 
        self.pathtestPDU=self.dirtestPDU+self.pair
        self.max_num =output_value
        
        #interest hex value , -256 +-2 , 65535 -1 -2
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

    def print_results(self,**kwargs):     
        print('                                                                              ', file=sys.stderr)                                                                             
        for name, value in list(kwargs.items()):
            print('{0} = {1}'.format(name, value))
        print('                                                                              ', file=sys.stderr)                                                                              
        return   

   
    def reset_coverage(self):  #go to test_case.py ?
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
        if fuzz_session.way in (0,1):fuzz_session.test_flag_fc=True  # test all , test FC public code
        fuzz_session.tmp_list_of_case=[]
        fuzz_session.fields_of_list=[]
        fuzz_session.tmp_test_list=[]
        fuzz_session.rows_of_cover=[]
        fuzz_session.flag_reguest=False              #Stop reguest //and fuzzer  
   
    def test_field_of_data(self,len_of_data): 
       '''
       This function  return replace a heuristic  length  valid or invalid for intersesting value or random 
       one char for field of data 
       len_of_data is test 0 f N byte to
       send data len of random string //ascii//all char//only alpanum//only one char
       '''
       f_of_data=b'' ; r=random.randint(0,100)                                           
       lgr.info('Fuzz test field of data, len_of_data: %d'% len_of_data)
       if len_of_data==0:return f_of_data
       
       if r<35:                                                                      
            lgr.info('all char');f_of_data= (''.join([chr(random.randint(0,255)) for i in range(0,len_of_data)])).encode()
            
       elif r<70:                                         
            lgr.info('ascii only');f_of_data= ''.join([chr(random.randint(0,128)) for i in range(0,len_of_data)]).encode() 
            
       elif r<80:     
            lgr.info('only alpanummeric');f_of_data= ''.join([chr((random.randint(0,96))+32) for i in range(0,len_of_data)]).encode() 
                                        
       else:                                            
            c=random.randint(0,96)+32 ; lgr.info('patterns one char : %r , 0x%02X ' % (c,c))         
            
            f_of_data = ''.join( [chr(c) for i in range(0,len_of_data)]).encode() 
       lgr.info('data_testing_field .. to 260 HexByte: %r' % ByteToHex(f_of_data [:260])); return f_of_data 
            
    def is_valid_combination( self,values, names,start_address=None,max_address=None):

        """ 
        Not use is example as FC43  PAIRWISE test
        rules Allpairs
        Read Device ID code                     Object Name
        DeviceInformation_Basic:  0x01,         range [0x00 -0x02]    
        DeviceInformation_Regular= 0x02 ,       range [0x03 -0x7F]
        DeviceInformation_Extended= 0x03 ,      range [0x80–0xFF] 
        DeviceInformation_Specific= 0x04 , 
        """
        dictionary = dict( list(zip( names, values )) )

        rules = [ 
                lambda d: 1 == d["Read Dev Id code"] and 0<=d["Object_Id"]<3 
                ,lambda d: 2 == d["Read Dev Id code"] and 3<=d["Object_Id"]<129
                ,lambda d: 3 == d["Read Dev Id code"] and 128<d["Object_Id"]<256
                   
                ]
            
        for rule in rules:
                try:
                    if rule(dictionary):
                        return False
                except KeyError: pass
                return True

    def loadpairsCSV(self,parameters,function_code): 
        
        """
        Pairwise test -FC15, FC16, FC23, FC43          
        load csv create of NIST-ACST/tools AllPairs/allpairspy, https://github.com/thombashi/allpairspy
        e.g FC16-Combinatorial(Quantity, byte_count, num of value)
        """
        
        global  csv_NIST;tfFC23=test_field_FC23();tfFC15=test_field_FC15(); tfFC16=test_field_FC16() ; tfFC43=test_field_FC43()    
        try:

            if os.path.exists(self.pathCSV%function_code):  
                # read CSV file & load into list
                with open(self.pathCSV%function_code, 'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwise = list([[int(x) for x in line] for line in pairwise_temp])
                    pairwise.sort(key = lambda row: (row[0],row[1],row[2]))
                    csv_NIST=True               
            else:
                    #Initializing from tools AllPairs ..  
                    if function_code == WRITE_MULTIPLE_REGISTERS:
                        is_valid_combinationfc=tfFC16.is_valid_combination_f16
                    elif function_code == WRITE_MULTIPLE_COILS:
                        is_valid_combinationfc=tfFC15.is_valid_combination_f15
                    elif function_code == Read_Write_Multiple_Registers:
                        is_valid_combinationfc=tfFC23.is_valid_combination_f23
                    elif function_code == Read_device_Identification:
                        is_valid_combinationfc=tfFC43.is_valid_combination_f43    
                    else:lgr.warn("    > Csv file not data   ..return");return np.empty((0,2)) #empty numpy array.             
                    
                    pairwise=list(AllPairs(   
                    [x[1] for x in parameters],
                    filter_func=lambda values: is_valid_combinationfc(
                        values, [x[0] for x in parameters])))

                    pairwise.sort(key = lambda row: (row[0],row[1],row[2])) #write ./    not dir='./Nist-csv'  in dir='./tmpAllpair' 
                    dir="./tmpAllpair";dir = os.path.normpath(dir)          
                    # Create a folder
                    if not os.path.exists(dir):os.makedirs(dir)          
                    # read CSV file & load in  list           
                    with open(dir+self.pair%function_code,"w") as f:
                        wr = csv.writer(f);wr.writerows(pairwise)                       
                    csv_NIST=False     

        except Exception  as er: lgr.error("     > %s,IOError CSV ..send zero values ..",str(er));return np.empty((0,2)) #empty numpy array.
            
        if len(pairwise)==0:lgr.warn("     > Csv file not data   ..return");return np.empty((0,2)) #empty numpy array.
                        
        lgr.info("     > Initializing from NIST-ACTS/AllPairs %s/%s, test: %d " % (csv_NIST, not csv_NIST,len(pairwise)))       
        return np.array(pairwise)        

    def pair(self,parameters,function_code):  #not use 

        """ 
        Pairwise test -FC15, FC16, FC23          
        load csv create of NIST-ACST/tools AllPairs
        e.g FC16-Combinatorial(Quantity, byte_count, num of value)
        """

        lgr.info("PAIRWISE list Initializes")
        try:
        
            if os.path.exists("FC%d_pair.csv"%function_code):
                # read CSV file & load into list
                with open("FC%d_pair.csv"%function_code,'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to Init
                    pairwise = list([[int(x) for x in line] for line in pairwise_temp])
            else:
                    pairwise=list(Allpairs(
                    [x[1] for x in parameters],
                    filter_func=lambda values: self.is_valid_combination_FC01(
                        values, [x[0] for x in parameters])))

                    pairwise.sort(key = lambda row: row[1])
            
        except IOError :
            lgr.warn("------- IOError, not file NIST-ACTS,  ..return");return np.array(pairwise)

        if not pairwise:
            raise ValueError ('no data')    
        

        lgr.info('     > Test case Initializing --------- : %d '% len(pairwise))
        return np.array(pairwise)

    def pairsCSV(self,function_code):  

        """ 
        case not calculate from tools AllPairs 
        FC20,FC21 file record access - pairwise test 
        load csv from  NIST-ACST in dir="./Nist-csv" or empty
        not initializing from tools AllPairs
        """
        global csv_NIST;pairwise=[]
              
        try:
        
            if os.path.exists(self.pathCSV%function_code): #catch, if not file NIST-ACTS...
                # read CSV file & load into list
                with open(self.pathCSV%function_code,'r') as f:#catch,  IOError...
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to Init
                    pairwise = list([[int(x) for x in line] for line in pairwise_temp])
                    pairwise.sort(key = lambda row: (row[0],row[1],row[2]) )
                    csv_NIST=True 
            else:  raise CsvError ("CSV not exist")                  
                                            
        #except IOError, catch problem in csv file 
        except  Exception  as er:  lgr.error("     > %s,IOError CSV ..send zero values ..",str(er));return np.array(pairwise)
       
        if  len(pairwise)==0: 
            lgr.warn("     > Csv file not data   ..return");return np.array(pairwise)
        return np.array(pairwise)
    
    def load_pair_file(self,parameters,function_code):

        """ 
        Pairwise test for FC01,FC02, FC03, FC04, FC05,FC06 load from  ./csvtestPDU,  as csv-defaults
        if not file heuristic csv, use itertools product 

        """
        global csv_heuristic,csv_NIST
        pairwise=[];lof=list_of_fuzz();lib_word=lof.lib_word_cart()
        
        if function_code==WRITE_MULTIPLE_COILS: function_code=READ_COILS  
        if function_code==WRITE_MULTIPLE_REGISTERS or function_code==Read_Write_Multiple_Registers:function_code=READ_HOLDING_REGISTERS  

        try:  #load from  ././csvtestPDU file csv 
            if os.path.exists(self.pathtestPDU%function_code):   
                # read CSV file & load into list
                with open(self.pathtestPDU%function_code,'r') as f:
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to Init
                    pairwise = np.array(list([[int(x) for x in line] for line in pairwise_temp]))
                    csv_heuristic=True #flag                            
            else:
                    #not file heuristic csv, use itertools product
                    csv_heuristic=False                    
                    if function_code==READ_COILS :                   
                        pairwise=list(itertools.product(fuzz_session.fuzz_addre_COILS_cart,fuzz_session.quantity_of_x_list_coil_cart))
                    elif function_code==READ_DISCRETE_INPUTS:
                        pairwise=list(itertools.product(fuzz_session.fuzz_addre_DIS_IN_cart,fuzz_session.quantity_of_x_list_coil_cart))
                    elif  function_code==READ_HOLDING_REGISTERS :
                        pairwise=list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart))
                    elif function_code==READ_INPUT_REGISTERS :
                        pairwise=list(itertools.product(fuzz_session.fuzz_addre_IN_REG_cart,fuzz_session.quantity_of_x_list_reg_cart))
                    elif function_code==WRITE_SINGLE_COIL :
                        pairwise=np.array(list(itertools.product(fuzz_session.fuzz_addre_COILS_cart,lib_word))) 
                    elif function_code==WRITE_SINGLE_REGISTER :
                        pairwise=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,lib_word)))
                                                                                                                  
                    dir="./tmpAllpair";dir = os.path.normpath(dir)
                    # Create a folder
                    if not os.path.exists(dir):os.makedirs(dir)                    
                    #save in ./tmpAllpair
                    with open(dir+self.pair%function_code,"w") as f:
                        wr = csv.writer(f);wr.writerows(pairwise)   
                        
                    pairwise.sort(key = lambda row: (row[0],row[1])) 
                    
                                  
        #except IOError, catch problem in csv file 
        except  Exception  as er:  lgr.error("     > %s,IOError CSV ..send zero values ..",str(er));return np.array(pairwise)
       
        if  len(pairwise)==0: 
            lgr.warn("     > Csv file not data   ..return");return np.array(pairwise)

        lgr.warn("     > Initializing heuristic csv/itertools.product %s/%s, test: %d " % (csv_heuristic, not csv_heuristic,len(pairwise)))  
        return np.array(pairwise)         

   
    def fuzz_field_pdu(self,pdu):

        """ This functions fuzzes a field of pdu  (** look specification Modbus)
            testing gramar for FC  01,02,03,04,5,6,15,16,23,21 22,43
            See Modbus spec v1.1b3
        """
        #remove pairwice_Read_device_Ident  
        global  slave,lib_word_binary,pairwice_WRITE_SINGLE_REGISTER,pairwice_WRITE_SINGLE_COIL,pairwice_READ_COILS,pairwice_READ_INPUT_REGISTERS,pairwice_READ_HOLDING_REGISTERS,pairwice_READ_DISCRETE_INPUTS
        function_code=int.from_bytes(pdu[0:1], byteorder='big')                     
        lgr.info('The function_code is: % s'  % function_code)  
        adu="" 
        
        if  function_code == Read_Exception_Status or function_code == Get_Comm_Event_Counter or function_code == Get_Comm_Event_Logs or function_code == Report_Slave_Id :
        	fuzz_session.test_flag_fc=False #not test FC
        while True:

            # case 1/test illegal FC
            if fuzz_session.test_flag_fc==True and fuzz_session.way in (0,1): # test only choice 1-way or all (0) 
                tfFC=test_field_FC()  #instantiate a class
                pdu=tfFC.fuzz_field_FC(function_code,pdu)
                break

            # case 2/1-way (single) and 2-way (pairwise) test parameter PDU
            if fuzz_session.test_flag_parameter_PDU==True:
                lgr.info('Testing parameter PDU')
                if function_code == READ_COILS :
                    lgr.info('FC 01: READ_COILS')
                    tfFC01=test_field_FC01()#instantiate a class
                    pdu=tfFC01.fuzz_field_parameter_FC01(function_code,pdu)
                    break
                elif function_code == READ_DISCRETE_INPUTS :    
                    lgr.info('FC 02: READ_DISCRETE_INPUTS')
                    tfFC02=test_field_FC02() #instantiate a class
                    pdu=tfFC02.fuzz_field_parameter_FC02(function_code,pdu)
                    break
                elif function_code == READ_HOLDING_REGISTERS :    
                    lgr.info('FC 03: READ_HOLDING_REGISTERS')
                    tfFC03=test_field_FC03() 
                    pdu=tfFC03.fuzz_field_parameter_FC03(function_code,pdu)
                    break

                elif function_code == READ_INPUT_REGISTERS :    
                    lgr.info('FC 04: READ_INPUT_REGISTERS')
                    tfFC04=test_field_FC04()
                    pdu=tfFC04.fuzz_field_parameter_FC04(function_code,pdu)
                    break    

                elif function_code == WRITE_SINGLE_COIL :    
                    lgr.info('FC 05: WRITE SINGLE COIL')
                    tfFC05=test_field_FC05()
                    pdu=tfFC05.fuzz_field_parameter_FC05(function_code,pdu)
                    break    
                
                elif function_code == WRITE_SINGLE_REGISTER :    
                    lgr.info('FC 06: WRITE_SINGLE_REGISTER')
                    tfFC06=test_field_FC06()
                    pdu=tfFC06.fuzz_field_parameter_FC06(function_code,pdu)
                    break 

                elif function_code == WRITE_MULTIPLE_COILS :    
                    lgr.info('FC 15: WRITE_MULTIPLE_COILS')
                    tfFC15=test_field_FC15()
                    pdu=tfFC15.fuzz_field_parameter_FC15(function_code,pdu)
                    break     

                elif function_code == WRITE_MULTIPLE_REGISTERS :    
                    lgr.info('FC 16: WRITE_MULTIPLE_REGISTERS')
                    tfFC16=test_field_FC16()
                    pdu=tfFC16.fuzz_field_parameter_FC16(function_code,pdu)
                    break     
                
                elif function_code == Mask_Write_Register :    
                    lgr.info('FC 22: Mask Write Register')
                    tfFC22=test_field_FC22()
                    pdu=tfFC22.fuzz_field_parameter_FC22(function_code,pdu)
                    break 

                elif function_code == Read_Write_Multiple_Registers :    
                    lgr.info('FC 23: Read_Write_Multiple_Registers')
                    tfFC23=test_field_FC23()
                    pdu=tfFC23.fuzz_field_parameter_FC23(function_code,pdu)
                    break 

                elif function_code == Read_File_record :    
                    lgr.info('FC 20: Read_File_record')
                    tfFC20=test_field_FC20()
                    pdu=tfFC20.fuzz_field_parameter_FC20(function_code,pdu)
                    break

                elif function_code == Write_File_record  :    
                    lgr.info('FC 21: Write_File_record ')
                    tfFC21=test_field_FC21()
                    pdu=tfFC21.fuzz_field_parameter_FC21(function_code,pdu)
                    break

                elif function_code == Read_FIFO_queue  :    
                    lgr.info('FC 24: Read_FIFO_queue')
                    tfFC24=test_field_FC24()
                    pdu=tfFC24.fuzz_field_parameter_FC24(function_code,pdu)
                    break 
                
                elif function_code == Read_device_Identification  :    
                    lgr.info('FC 43: Read_device_Identification')
                    tfFC43=test_field_FC43() #instantiate a class
                    pdu=tfFC43.fuzz_field_parameter_FC43(function_code,pdu)
                    break
                
                #Serial  FC  except Diagnostics
                #defaults test case from class TestQueriesSerialFC  and test_DiagnosticRequests()
                #if flag_test_FC08_pair=True then test 2-way and
                #test case from class TestQueriesSerialFC and def
                #test_DiagnosticRequests_data_field
                elif function_code == Diagnostics :    
                    lgr.info('FC 8: Diagnostics ')
                    fuzz_session.flag_test_FC08_pair=True
                    tfFC8=test_field_FC08() #instantiate a class                    
                    pdu=tfFC8.fuzz_field_parameter_FC08(function_code,pdu)
                    break 

                elif function_code == Read_Exception_Status :    
                    lgr.info('FC 7: Read_Exception_Status/not parameters PDU ')
                    fuzz_session.flag_reguest=False                    
                    break

                elif function_code == Get_Comm_Event_Counter :    
                    lgr.info('FC 11: Get_Comm_Event_Counter/not parameters PDU ')
                    fuzz_session.flag_reguest=False
                    break             
                
                elif function_code == Get_Comm_Event_Logs  :    
                    lgr.info('FC 12: Get_Comm_Event_Logs / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break   
                
                elif function_code == Report_Slave_Id  :    
                    lgr.info('FC 17: Report_Slave_Id / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break    
                
                else:
                    fuzz_session.FCmergedlist.insert(len(fuzz_session.FCmergedlist)+1,fuzz_session.FCmergedlist.pop(0))    #list rotate
                    lgr.info('Function_code: %d ....' % function_code)
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


class test_field_FC(object):
    

    def __init__(self): 
        
        """
        
        """
    def fuzz_field_FC(self,function_code,pdu):

        """
        The functions below testing field FC
        FC List Public codes the non-contiguous ranges {1-64, 73-99, 111-127}.
        User-defined codes in the ranges {65-72, 100-110}, Modbus exception codes {128-255}
        """ 
        fp=fuzzer_pdu()
        if  fuzz_session.flag_public_codes==True:
            # Making a flat list out of list of lists
            if  len(fuzz_session.public_codes)==0 :
                fuzz_session.public_codes=fp.public_codes 
                try :
                    fuzz_session.public_codes.remove(function_code)
                except:
                    pass    
                
            function_code = fuzz_session.public_codes[0]           
            lgr.warn('case 1: public codes {1-64, 73-99, 111-127}')                                                           
            lgr.warn('test public code: %d ..0x%02X ..' % (function_code,function_code))
                      
            fuzz_session.public_codes.pop(0) 
            
            if len(fuzz_session.public_codes)==0 :
                fuzz_session.flag_public_codes=False
                
        elif  fuzz_session.flag_user_codes==True:
            if len(fuzz_session.user_codes)==0 :
                fuzz_session.user_codes=fp.User_defined_codes
            
            function_code = fuzz_session.user_codes[0]
            lgr.warn('case 2: user-defined codes {65-72, 100-110}')                                                        
            lgr.warn('test user-defined function code: %d ..0x%02X ..' % (function_code,function_code ))

            fuzz_session.user_codes.pop(0)
            if len(fuzz_session.user_codes)==0 :
                fuzz_session.flag_user_codes=False
              
        elif  fuzz_session.flag_exeption_codes==True :         
            if len(fuzz_session.exeption_codes)==0 :
                fuzz_session.exeption_codes=fp.exeption_codes
            function_code = fuzz_session.exeption_codes[0]
            
            lgr.warn('case 3: exeption function codes {128-255}')                                                           
            lgr.warn('test exeption code: %d ..0x%02X ..' % (function_code,function_code)) 

            fuzz_session.exeption_codes.pop(0)
            if len(fuzz_session.exeption_codes)==0 :
                
                fuzz_session.flag_user_codes=False               #not run for another FC
                fuzz_session.flag_public_codes=True
                fuzz_session.test_flag_fc=False
                fuzz_session.test_flag_parameter_PDU=True        #next test for FC                   
               
        return  struct.pack(">B", function_code)+pdu[1:]   
        
class test_field_FC08(object):

    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535

    def fuzz_field_parameter_FC08(self,function_code,pdu):
    
        '''08 (0x08) Diagnostics (Serial Line only)
        1-way sub-function code test ,data field "\x00\x00" or randomize
        global -fuzz_session.Diagnostics_FC_param=['sub-function','data','2-way' ]
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
            is_way('2-way')                                                                      #Choice single or pairwise test of fields
            
        test_field = fuzz_session.fields_of_list[0]; lgr.info('testing field: % r ' % test_field)                                
                               
        if test_field=='sub-function' :                                                                                                     
            subfunction=fuzz_session.lib_test_sub_diag[0]
            fuzz_session.lib_test_sub_diag.append(fuzz_session.lib_test_sub_diag.pop(0))           #shift a list
            
        elif test_field=='data' :
            data=fuzz_session.values_test[0]
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))                        
                
        #test case from class TestQueriesSerialFC and def test_Diagnostics Requests_data_field    
        elif test_field=='2-way':  
            lgr.info('test Diagnostics Requests..sub Code vs data')
            if fuzz_session.flag_test_FC08_pair==True:pass
            else:
                fuzz_session.flag_reguest=False               #Stop reguest /and fuzzer
                fuzz_session.test_flag_parameter_PDU=True     #test parameter_PDU
                fuzz_session.test_flag_fc=False               #disable//enable test FC for next FC
              
        else :
            lgr.warn('\n \t \t \t ...error testing diagnostics subcodes..and data fail')
            not_exist_field(test_field)  #case not exist field  of test 
        
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
      
        #check -if and  test 'data', fuzz_session.flag_reguest=False, stop reguest from  tsf.test_DiagnosticRequests() 
        #in class TestQueriesSerialFC ,fuzz_session.l_output_value=fuzz_session.values_test[-1]
        if  (subfunction== fuzz_session.l_item_test_sub_diag and test_field=='sub-function') \
        or (data==fuzz_session.l_output_value and test_field=='data' ) :
                        
            if test_field=='sub-function':
                tcc.Coverage (function_code,test_field, fuzz_session.Diagnostics_FC_param,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='data':
                tcc.Coverage (function_code,test_field, fuzz_session.Diagnostics_FC_param,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
                fuzz_session.flag_reguest=False                
                         
            tcc.test_case (function_code,test_field,fuzz_session.Diagnostics_FC_param,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0))
            
        if data <0:return  struct.pack(">BHi", function_code,subfunction,data) 
        else :return  struct.pack(">BHH", function_code,subfunction,data)   
    
class test_field_FC24(object):

    def __init__(self): 
        
        """
        
        """

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
        fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))    #shift a list

        if fuzz_session.Pointer_address==fuzz_session.l_fuzz_addre_HO_REG:            
            lgr.warn('error....FC24 ') 
            fuzz_session.flag_reguest=False              #Stop reguest //and fuzzer        
        
        return struct.pack(">BH", function_code,fuzz_session.Pointer_address)                     


class test_field_FC23(object):

    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535
        self.t1byte=256

    def fuzz_field_parameter_FC23(self,function_code,pdu,case_FC23=None,output_value=None):    
        """ 
        23 /( 0x17) Read_Write_Multiple_Registers - 1-way/single test
        field Read address, Read REGISTERS Quantity to Read 0x0001 to 0x007D
        field Write address  vs Write REGISTERS quantity (0x0001 - 0x0079)
        Quantity of Registers (0x0001 to 0x007B) 
        byte_count (2 x N*) N = Quantity of Registers,
        fuzz_session.test_FC_23=['1-way_read_starting_address', '1-way_quantity_to_Read','1-way_write_starting_address',/
        '1-way_quantity_to_Write','1-way_write_byte_count','2-way'] 
        fuzz_session.flag_boundaries=0 reset
        Write Registers Value Combinatorial test in '2-way'        
        """
         
        read_starting_address, quantity_to_Read, write_starting_address, quantity_to_Write,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
        message_data=pdu[10:]
        tcc=test_case_coverage();fuzz_session.flag_boundaries=0

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_FC_23[:]
            is_way('2-way')                                         #look choice 1-way ,2-way test 
 
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)    
                                   
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
            #raise
            not_exist_field(test_field)                           
        
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
            lgr.warn('Write REGISTERS quantity invalid (out of spec): %d ..0x%02X ..' % (quantity_to_Write,quantity_to_Write))
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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='1-way_quantity_to_Read':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            if test_field=='1-way_write_starting_address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            if test_field=='1-way_quantity_to_Write':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            if test_field=='1-way_write_byte_count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC_23,fuzz_session.field5_valid, fuzz_session.field5_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            tcc.test_case (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.tmp_test_list)
            fuzz_session.tmp_test_list=[]
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()     
       
        fuzz_session.read_starting_address=read_starting_address
        fuzz_session.write_starting_address=write_starting_address
        fuzz_session.quantity_to_Read=quantity_to_Read
        fuzz_session.write_byte_count=write_byte_count
        fuzz_session.quantity_to_Write=quantity_to_Write

        pdu= struct.pack(">BHHHHB",function_code,read_starting_address, quantity_to_Read, write_starting_address,quantity_to_Write,write_byte_count)
        pdu += message_data    
        return pdu

        
    def fuzz_field_two_way_parameter_FC23(self,function_code,pdu,case_FC23=None,output_value=None):
        """ 
        Test case Initializing 
        23 /( 0x17) Read_Write_Multiple_Registers
        case 1: field Read address  vs Read REGISTERS Quantity to Read 0x0001 to 0x007D (CSV file FC03 from  library ./libraries/pairs_address, heuristic )
        case 2: field Write address  vs Write REGISTERS quantity (0x0001 - 0x0079) (CSV file FC16 from NIST-ACTS)
        case 3: Quantity of Registers/write (0x0001 to 0x007B) vs byte_count (2 x N*) N = Quantity of Registers, vs output_value(CSV file from NIST-ACTS)

        # ACTS Test Suite Generation: Wed Mar 24 13:01:37 EET 2021
        #  '*' represents don't care value 
        # Degree of interaction coverage: 2
        # Number of parameters: 3
        # Maximum number of values per parameter: 145
        # Number of configurations: 10738
        # quan_write,byte_count,num_value

        # for All pair toolS /allpairspy, https://github.com/thombashi/allpairspy
        # ./tools/Allpairs_201-csv/script/case_fc23.py
        # Test case Initializing quantity: 71
        # Test case Initializing byte_count: 60
        # Test case Initializing num_values: 141
        # PAIRWISE list Initializes
        # Test case Initializing : 6816
        
        #flag csv_heuristic,heuristic csv/itertools.product
        #flag csv_NIST  Combinatorial from NIST-ACTS/AllPairs

        """
        global pairwice_READ_HOLDING_REGISTERS,pairwice_Quant_vs_byte_count,csv_heuristic,csv_NIST
        tcc=test_case_coverage();fp=fuzzer_pdu();parameters=[];lof=list_of_fuzz()
        case_FC23=fuzz_session.case_FC23
        #Decode the request valid packet
        read_starting_address, quantity_to_Read, write_starting_address, quantity_to_Write,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
        message_data=pdu[10:]
             
        while True:
            # case 1: field Read address vs Read REGISTERS quantity 
            if case_FC23==True:
               
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 : 
                    
                     pairwice_READ_HOLDING_REGISTERS=fp.load_pair_file (parameters,function_code)
                
                lgr.warn('     > case 1: heuristic csv/itertools.product %s/%s for Read address vs Read Registers quantity, remain test: %d'%(csv_heuristic, not csv_heuristic, len(pairwice_READ_HOLDING_REGISTERS)-1))

                starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                
                if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
                    lgr.warn('Read address  invalid: %d ..0x%02X ..' % (starting_address,starting_address))
                else :
                    lgr.info('Read address  valid: %d ..0x%02X ..' % (starting_address,starting_address))
                       
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
                #for case1 : Read REGISTERS quantity =fuzz_session.quantity_of_x 
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
            # case 2 pairs field Write address vs Write REGISTERS quantity (0x0001 - 0x0079)     
            elif case_FC23==False: 
                
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    pairwice_READ_HOLDING_REGISTERS=fp.load_pair_file (parameters,function_code)
                
                lgr.warn('     > case 2: heuristic csv/itertools.product %s/%s for Write address vs Write Registers, remain test: %d'%(csv_heuristic, not csv_heuristic, len(pairwice_READ_HOLDING_REGISTERS)-1))
     
                starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]   
        
                if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
                    
                    lgr.warn('Write address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
                else :
                    lgr.info('Write address valid: %d ..0x%02X ..' % (starting_address,starting_address))
                    
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                # quantity_to_Write  Quantity of Write (0x0001 - 0x0079)  
                if fuzz_session.quantity_of_x >121 or fuzz_session.quantity_of_x==0:                        
                    lgr.warn('Write REGISTERS quantity invalid (out of spec): %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Write REGISTERS quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_HO_REG :
                    fuzz_session.flag_boundaries=1
                    lgr.warn('(write address + quantity of write) is invalid : %d ..0x%02X ..' % ((starting_address+fuzz_session.quantity_of_x),starting_address+fuzz_session.quantity_of_x))
                else :  
                    lgr.info('(Write address + quantity of write) is  valid: %d ..0x%02X ..' % ((starting_address+fuzz_session.quantity_of_x),starting_address+fuzz_session.quantity_of_x))  
                    
                #for case2 : fuzz_session.quantity_of_x=Write REGISTERS quantity 
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
            else :# case 3, Combinatorial NIST-ACTS/AllPairs, Quantity_of_Reg write vs Byte_count vs output_value
                  # calculate byte_count, num_value, from class list fuzz heuristics library                           
                parameters_FC23 = [ 
                               ("quantity_write"
                               , fuzz_session.quantity_of_x_list_reg_cart)
                             , ( "byte_count"
                               ,fuzz_session.byte_count_test)#def lib_byte_test in class list fuzz heuristics library
                             ,  ( "num_value"
                               ,lof.illegal_len_list() )                               
                             ]
                
                if  len(pairwice_Quant_vs_byte_count)==0 : 
                    pairwice_Quant_vs_byte_count=fp.loadpairsCSV(parameters_FC23,function_code)
                                                   
                lgr.warn('     > case 3: NIST-ACTS/AllPairs %s/%s,Combinatorial (Quantity of Reg write vs Byte count vs output value),test: %d '%(csv_NIST, not csv_NIST,len(pairwice_Quant_vs_byte_count)))

                #Quantity of Write (0x0001 - 0x0079)
                fuzz_session.quantity_to_Write=pairwice_Quant_vs_byte_count[0][0]
                write_byte_count=pairwice_Quant_vs_byte_count[0][1]

                if (fuzz_session.quantity_to_Read >125) or (fuzz_session.quantity_to_Read==0):
                    lgr.warn('Read REGISTERS quantity invalid (out of spec): %d ...0x%02X..' % (fuzz_session.quantity_to_Read,fuzz_session.quantity_to_Read))
                else :
                    lgr.info('Read REGISTERS quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_to_Read,fuzz_session.quantity_to_Read))


                if fuzz_session.quantity_to_Write>121 or fuzz_session.quantity_to_Write==0:
                    lgr.warn('Write quantity invalid (out of spec): %d ..0x%02X ..' % (fuzz_session.quantity_to_Write,fuzz_session.quantity_to_Write))
                else :
                    lgr.info('Write quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_to_Write,fuzz_session.quantity_to_Write))

                if write_byte_count >2*121 or write_byte_count==0:
                    lgr.warn('Write byte count invalid (out of spec): %d ..0x%02X ..' % (write_byte_count,write_byte_count))
                #byte_count (2 x N*) N = Quantity of Registers
                else :
                    if  write_byte_count!=2*fuzz_session.quantity_to_Write:lgr.warn('Byte count (not consisten Quantity): %d , 0x%02X...' % (write_byte_count,write_byte_count))
                    else: lgr.info('Write byte count valid: %d ..0x%02X ..' % (write_byte_count,write_byte_count))
 
                output_value=pairwice_Quant_vs_byte_count[0][2]*[fp.output_values[0]]

                lgr.info('value:0x{%02X}.., num_values: %d' % (fp.output_values[0],pairwice_Quant_vs_byte_count[0][2]))
                lgr.info('Byte of data value: %d' % (2*(len(output_value))))
                fp.output_values.append(fp.output_values.pop(0))      
                
                pdu= struct.pack(">BHHHHB",function_code,read_starting_address, fuzz_session.quantity_to_Read, write_starting_address,quantity_to_Write,write_byte_count)
                fuzz_session.tmp_test_list.append ([read_starting_address,fuzz_session.quantity_of_x,write_starting_address, quantity_to_Write,write_byte_count])
                pairwice_Quant_vs_byte_count=np.delete(pairwice_Quant_vs_byte_count, 0, 0)
                for j in  output_value:
                        fmt="H" if j>=0 else "h"
                        pdu +=struct.pack(">" + fmt,j)
                                                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    tcc.test_case (function_code,'Quant_vs_byte_count',['address','quantity_of_x','byte_count','write_starting_address','quantity_to_Write','write_byte_count'],np.array(fuzz_session.tmp_test_list))                    
                    fp.reset()
                    fuzz_session.case_FC23=True                   
                break
        return pdu

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
        dictionary = dict( list(zip( names, values )) )

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
            

class test_field_FC21(object):
    
    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535
        self.t1byte=256

    def fuzz_field_parameter_FC21(self,function_code,pdu):
        """
        Write File Record  FC 21
        test one-field, the rest valid   - 
        fuzz_session.test_field_Write_File_record=['Data_length','Reference_Type','File number','Record number','Record_length',Record data',2-way']
        file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
        self.record_length = kwargs.get('record_length', len(self.record_data) // 2)
        max value for self.record_data  is 244 Byte, self.record_length=max N=122X2 byte
        record1 = FileRecord(file_number=0x01, record_number=0x02, record_data=b'\x00\x01\x02\x04') 
         
        """        
        global pairwice_file
        tcc=test_case_coverage();fp=fuzzer_pdu()

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_Write_File_record[:]
            is_way('2-way')  

        test_field = fuzz_session.fields_of_list[0]                                                    
        lgr.info('testing field: % r ' % test_field)
                                                                       
        #first group, record1
        Data_length,Reference_Type,File_number,Write_record,Record_length= struct.unpack(">BBHHH", pdu[1:9])
        Record_data=pdu[9:13]
        #other group
        other_group=pdu[14:]
    
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
            Record_data =fp.test_field_of_data(fuzz_session.fuzz_files_rec[0]) 
            fuzz_session.fuzz_files_rec.append(fuzz_session.fuzz_files_rec.pop(0))
        
        elif test_field=='2-way':              
            #only test group 0 and Record_data to interest bytes/value
            Data_length,Reference_Type,File_number,Write_record,Record_length,output_value=self.fuzz_field_two_way_parameter_FC21(function_code,pdu)            
            output_value=[fp.output_values[0]]
            for j in  output_value:
                    fmt="H" if j>=0 else "h"
                    Record_data =struct.pack(">" + fmt,j)
            
            fp.output_values.append(fp.output_values.pop(0))    #next  interest bytes/value        
                      
        else :
            not_exist_field(test_field)  # case not exist field  of test
  
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

        if Record_length==(len(Record_data)//2):
            lgr.info('Record_length value valid: %d ..0x%02X..' % (Record_length,Record_length))
            fuzz_session.field5_valid += 1  
        else :
            lgr.warn('Record_length value  invalid: %d ..0x%02X..' % (Record_length,Record_length))
            fuzz_session.field5_invalid += 1

        if (len(Record_data))<=244:                  #record_length=max N=122X2 byte for len 260 packet
            lgr.info('Record data len value valid: %d ..0x%02X..' % (len(Record_data),len(Record_data)))
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
            (test_field=='Record data' and (fuzz_session.fuzz_files_rec[-1]==fuzz_session.l_fuzz_files_rec)) : ##Value of test files records data:fuzz_session.fuzz_files_rec[-1], last item,len of fuzz testing record data,fuzz_session.fuzz_files_rec=interesting value*byte(ascii,alfa, only one)
            
            if test_field=='Data length':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            if test_field=='Reference Type':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            if test_field=='File number':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)     
            
            if test_field=='Record number':                  
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)     
            
            if test_field=='Record length':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field5_valid, fuzz_session.field5_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)
            
            if test_field=='Record data':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.field6_valid, fuzz_session.field6_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)

            tcc.test_case (function_code,test_field,fuzz_session.test_field_Write_File_record,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]

            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp.reset()             
        
        elif (len(pairwice_file)==0 and test_field=='2-way'):
            
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field4_valid,fuzz_session.field4_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field5_valid,fuzz_session.field5_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field6_valid,fuzz_session.field6_invalid])            
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_Write_File_record,fuzz_session.tmp_list_of_case,t=self.t2byte) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_Write_File_record,np.array(fuzz_session.tmp_test_list))
            fp.reset() 
            
        record1 = (File_number,Write_File_record,Record_length)
        fuzz_session.f_record1 ='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Write_record,Record_length) #only first group fuz test
        #fuzz_session.f_record1 = [record1]
        pdu  = struct.pack(">BBBHHH",function_code,Data_length,Reference_Type,File_number,Write_record,Record_length)                  
        pdu += Record_data       
        return pdu +other_group 

    def fuzz_field_two_way_parameter_FC21(self,function_code,pdu):
        """
        Write File Record  FC 21
        file_number: 0-0xffff  record_number:0-0x270f  record_length=N *2 byte
        self.record_length   = kwargs.get('record_length', len(self.record_data) // 2)
        record_num =(0,9999)

        ACTS Test Suite Generation: Thu Nov 04 11:35:24 EET 2021
          '*' represents don't care value 
        Degree of interaction coverage: 2
        Number of parameters: 6
        Maximum number of values per parameter: 183
        Number of configurations: 7267
        Data_length,Reference_Type,File_number,Record_number,Record_length,Record_data

        """
        global pairwice_file,csv_NIST ;fp=fuzzer_pdu()  
        if  len(pairwice_file)==0 :
            pairwice_file=fp.pairsCSV (function_code)
            if len(pairwice_file)==0 :csv_NIST=False; fp.reset();return   0,0,0,0,0,0  #return   0,0,0,0,0,0 one test, and next FC
                                                    
        lgr.warn('     > Combinatorial NIST-ACTS/not file, %s/%s (Byte_count,Reference_Type,File_number,File_record,Record_length,output_value),remain test: %d'% (csv_NIST, not csv_NIST,len(pairwice_file)-1))       

        #and output_value for record data
        Data_length=pairwice_file[0][0];Reference_Type=pairwice_file[0][1]       
        File_number=pairwice_file[0][2];Write_File_record=pairwice_file[0][3]        
        Record_length =pairwice_file[0][4];output_value=pairwice_file[0][5]     
        pairwice_file=np.delete(pairwice_file, 0, 0)       
        #return   Reference_Type,File_number,Write_File_record,Record_length #grup 0
        return   Data_length,Reference_Type,File_number,Write_File_record,Record_length,output_value 
    

class test_field_FC20(object):
    
    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535
        self.t1byte=256

    def fuzz_field_parameter_FC20(self,function_code,pdu):  
        """
       20 (0x14) Read File Record-test only first group
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
       'test_field_Read_File_record':['Byte_Count','Reference_Type','File_number','Record_number','Record_length','2-way'],
            
       """
        
        global pairwice_file
        tcc=test_case_coverage()

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_Read_File_record[:]
            is_way('2-way')    
      
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
            not_exist_field(test_field)  #case not exist field  of test

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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            if test_field=='Reference_Type':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            if test_field=='File_number':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)     
            
            if test_field=='Record_Number':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)     
            
            if test_field=='Record_length': 
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.field5_valid, fuzz_session.field5_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_Read_File_record,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            fuzz_session.fields_of_list.pop(0)
            #fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) #rotate
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()            
               
        
        elif (len(pairwice_file)==0 and test_field=='2-way'):
            
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field4_valid,fuzz_session.field4_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field5_valid,fuzz_session.field5_invalid])            
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_Read_File_record,fuzz_session.tmp_list_of_case,t=self.t2byte) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_Read_File_record,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu(); fp.reset() 
            
        record1 = (File_number,Read_File_record,Record_length)
        fuzz_session.f_record1 ='FileRecord(file=%d, record=%d, length=%d)' % (File_number,Read_record,Record_length) 
        return  struct.pack(">BBBHHH",function_code,Byte_Count,Reference_Type,File_number,Read_record,Record_length)

    
    def fuzz_field_two_way_parameter_FC20(self,function_code,pdu):
        
        """20 (0x14) Read File Record
        file_number: 0-0xffff   record_number:0-0x270f  record_length=N *2 byte
        record_length   = kwargs.get('record_length', len(self.record_data) // 2)
        record_num =(0,9999)

        ACTS Test Suite Generation: Tue Nov 02 08:59:50 EET 2021
          '*' represents don't care value 
        Degree of interaction coverage: 2
        Number of parameters: 5
        Maximum number of values per parameter: 75
        Number of configurations: 5591
        Byte_count,Reference_Type,File_number,Record_number,Record_length
           
        """
        global pairwice_file,csv_NIST;fp=fuzzer_pdu()
        
        #NIST-ACTS-csv  file Initializes,  
        if  len(pairwice_file)==0 :
                pairwice_file=fp.pairsCSV (function_code)
                if len(pairwice_file)==0 :csv_NIST=False; fp.reset();return   0,0,0,0,0  #return   0,0,0,0,0 one test and next FC
                                  
                             
        lgr.warn('     > Combinatorial NIST-ACTS/not file, %s/%s (Byte_count,Reference_Type,File_number,Read_File_record),remain test: %d'% (csv_NIST, not csv_NIST,len(pairwice_file)-1))                        
        
        #Check group) // 4 parameter 
        Byte_Count=pairwice_file[0][0];Reference_Type=pairwice_file[0][1]
        File_number=pairwice_file[0][2];Read_File_record=pairwice_file[0][3]     
        Record_length =pairwice_file[0][4]     
        pairwice_file=np.delete(pairwice_file, 0, 0)
     
        return  Byte_Count,Reference_Type,File_number,Read_File_record,Record_length  
   
class test_field_FC22(object):
    
    def __init__(self): 
        
        """
        
        """

        self.t2byte=65535

    def fuzz_field_parameter_FC22(self,function_code,pdu):
        """ 
        22 (0x16) Mask Write Register
        param :address=0x0000, and_mask=0xffff, or_mask=0x0000
        This function code is used to modify the contents of a specified holding register 
        The normal response is an echo of the request. 
        testing one-way/single field as list fuzz_session.attack_byte_PDU -only
        global -fuzz_session.test_wr_mask_param=['address', 'or_mask', 'and_mask'] 
        Attension !!if choice way=2 pairwise  send test for testing one-way/single field
           
        """
        fuzz_session.flag_boundaries=0
        tcc=test_case_coverage()                                
        starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_wr_mask_param[:]

        test_field = fuzz_session.fields_of_list[0];lgr.info('testing field: % r ' % test_field)
        lgr.info('Only testing one-way (single field)')                                   
        
        if test_field=='address' :                                     
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))   #shift a list
            
        elif test_field=='or_mask' :
            or_mask= fuzz_session.values_test[0]            
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))                #shift a list
        
        elif test_field=='and_mask' :
            and_mask= fuzz_session.values_test[0]           
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))
           
        else :     #if problem in list of test '{0!s} {0!r}'.format(Data())     
            not_exist_field(test_field)

        #check address    
        if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('address invalid: %d ...0x%02X .' % (starting_address,starting_address))
            fuzz_session.field1_valid  += 1;fuzz_session.flag_boundaries=1 
                         
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
            
        lgr.info('or_mask: %d ..0x%02X ..' % (or_mask,or_mask))
        fuzz_session.field2_valid += 1
        lgr.info('and_mask: %d ..0x%02X ..' % (and_mask,and_mask))
        fuzz_session.field3_valid += 1

        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,and_mask,or_mask])
       
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_value_last item of list
        if  starting_address==fuzz_session.l_fuzz_addre_HO_REG or or_mask==fuzz_session.l_output_value or and_mask==fuzz_session.l_output_value  :
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_wr_mask_param,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='or_mask':
                tcc.Coverage (function_code,test_field,fuzz_session.test_wr_mask_param,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            if test_field=='and_mask':
                tcc.Coverage (function_code,test_field,fuzz_session.test_wr_mask_param,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
                                    
            tcc.test_case (function_code,test_field,fuzz_session.test_wr_mask_param,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[];fuzz_session.fields_of_list.pop(0)    
                               
            if  len(fuzz_session.fields_of_list)==0 :
                fp=fuzzer_pdu(); fp.reset()
                
        fuzz_session.starting_address=starting_address
        fuzz_session.and_mask=and_mask
        fuzz_session.and_mask=or_mask
        if and_mask <0:return  struct.pack(">BHiH", function_code,starting_address,and_mask,or_mask) # use 32bit value
        elif or_mask <0:return  struct.pack(">BHHi", function_code,starting_address,and_mask,or_mask) 
        else :return  struct.pack(">BHHH", function_code,starting_address,and_mask,or_mask)    


class test_field_FC16(object):
    
    def __init__(self): 
        
        """
        """
        self.t2byte=65535
        self.t1byte=256

    def fuzz_field_parameter_FC16(self,function_code,pdu,case_FC16=None,output_value=None):

        """
        testing one-way field in list global fuzz_session.test_field_mult_fc
        fuzz_session.test_field_mult_fc=['address', 'quantity_of_x','byte_count' '2-way'] 
        fuzz_session.quantity_of_x_list_coil or fuzz_session.quantity_of_x_list_reg   in def Read_CSvFile
        Registers Value Combinatorial test in '2-way'     
        """
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6]); output_value=pdu[6:]
        tcc=test_case_coverage();fp=fuzzer_pdu()
        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_mult_fc[:]
            is_way('2-way')  
            
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)
        
        if test_field=='address' :                                                    
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))                 #shift a list
        
        elif test_field=='quantity_of_x' :           
            quantity_of_x= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))       #shift a list
        
        elif test_field=='byte_count' : 
            byte_count= fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))  
        
        elif test_field=='output_value' :                  
            output_value =fp.test_field_of_data(fuzz_session.output_value_test[0])                      #heuristic  length  valid or invalid for intersesting value 
            fuzz_session.output_value_test.append(fuzz_session.output_value_test.pop(0))

        elif test_field=='2-way':
            return self.fuzz_field_two_way_FC16(function_code,pdu,case_FC16=None,output_value=None)       
        
        else :                                                                                          #raise
            not_exist_field(test_field) 
        
        if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1; fuzz_session.flag_boundaries=1
           
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1; fuzz_session.flag_boundaries=0
           
        
        if quantity_of_x >123 or quantity_of_x==0:
            lgr.warn('Write HOLDING_REGISTERS quantity invalid (out of spec): %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('Write HOLDING_REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_valid += 1
                
        if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_HO_REG :
            lgr.warn('(address + quantity) is invalid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_invalid += 1
            fuzz_session.flag_boundaries=1     
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1
            fuzz_session.flag_boundaries=0     
        
        if byte_count >2*123 or byte_count==0:
            lgr.warn('Write byte_count invalid (out of spec): %d ....' % byte_count)
            fuzz_session.field3_invalid += 1
        else :
            lgr.info('Write byte_count valid: %d ....' % byte_count)
            fuzz_session.field3_valid += 1 

        if (len(output_value)>246):                                 #len (output_value)=246, max N * 2byte for len 260 packet,  output_value=pdu[6:]
            lgr.info('Output data len value invalid: %d ....' % len(output_value))
            fuzz_session.field4_invalid += 1  
        else :
            lgr.info('Output_data len value valid: %d ....' % len(output_value))
            fuzz_session.field4_valid += 1

        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
        #check -fuzz_session.l_fuzz_addre_REG,fuzz_session.l_quantity_of_reg last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_HO_REG)  \
        or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_REG)  \
        or (test_field=='byte_count' and byte_count==fuzz_session.l_count_byte_test) \
        or (test_field=='output_value' and fuzz_session.output_value_test[-1]==fuzz_session.l_output_value_test): #last element of output_value_test
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            if test_field=='byte_count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 
            
            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_mult_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]                        
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()  
        
        fuzz_session.starting_address=starting_address;fuzz_session.quantity_of_x=quantity_of_x
        fuzz_session.byte_count=byte_count
        pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x,byte_count)
        pdu += output_value 
        return  pdu
            
        
    def fuzz_field_two_way_FC16(self,function_code,pdu,case_FC16=None,output_value=None):
        """
        Test case Initializing
        case 1 itertools.product pairs of address HO_REG and integer_boundaries  quantity_of_x_list)
        case 2 Quantity of Registers (0x0001 to 0x007B) vs byte_count (2 x N*) N = Quantity of Registers vs output_value
        """
        global pairwice_READ_HOLDING_REGISTERS,pairwice_Quant_vs_byte_count,csv_heuristic,csv_NIST
        tcc=test_case_coverage();fp=fuzzer_pdu();lof=lof=list_of_fuzz()
     
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:];parameters=[] 
        case_FC16=fuzz_session.case_FC16
        
        while True:
            # case 1
            if case_FC16==True:
               
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 : 
                    pairwice_READ_HOLDING_REGISTERS=fp.load_pair_file (parameters,function_code)
                    if len(pairwice_READ_HOLDING_REGISTERS)==0 : fp.reset();return  pdu #return  pdu (not fuzz) one test and next FC

                lgr.warn('     > case 1: heuristic csv/itertools.product %s/%s  for s_address vs Quantity, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_READ_HOLDING_REGISTERS)-1))
                
                starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
                               
                if (starting_address <fuzz_session.MIN_HO_REG) or (starting_address>fuzz_session.MAX_HO_REG):
                   
                   lgr.warn('address invalid: %d ..0x%02X..' % (starting_address,starting_address))
                   fuzz_session.flag_boundaries=1
                else :
                    lgr.info('address valid: %d ..0x%02X..' % (starting_address,starting_address))
                    fuzz_session.flag_boundaries=0

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
               
                lgr.info('byte_count: %d..0x%02X' % (byte_count,byte_count)); lgr.info('len output_value: %d' % len(output_value))
               
                fuzz_session.starting_address=starting_address
                pdu = struct.pack(">BHHB", function_code, starting_address, fuzz_session.quantity_of_x,byte_count)
                pdu +=output_value      
                
                fuzz_session.tmp_test_list.append ([starting_address,fuzz_session.quantity_of_x,byte_count,len(output_value)])
                pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)
                               
                if  len(pairwice_READ_HOLDING_REGISTERS)==0 :
                    #to case2
                    tcc.test_case (function_code,'address vs quantity',['address', 'quantity_of_x','byte_count','output_value'],np.array(fuzz_session.tmp_test_list))
                    fuzz_session.tmp_test_list=[];fuzz_session.case_FC16=False                   
                break    
                    
            elif case_FC16==False:
            # case 2
            # combinatorial parameter >> Quantity of Registers (0x0001 to 0x007B)
            # vs byte_count (2 x N*) > calculate byte_count from class list_of_fuzz and def lib_interesting_256() 
            # vs Registers Value=(Quantity of Registers OR num_values=N)*2B,
            # byte_count,integer fuzz heuristics library  lib_interesting_256(),
            # output_value, fuzz heuristics library for illegal len frame 

            # ./tools/Allpairs_201-csv/script/case_fc16.py
            # fuzz_session.quantity_of_x_list_reg_cart(from def calc_quantity_fuzz) val:71
            # lof.lib_interesting_256()   val:60
            # lof.illegal_len_list() val:141

            # calculate CSV from AllPair tools allpairspy, https://github.com/thombashi/allpairspy//use less value from NIST-ACTS 
            # for Allpair tools (allpairspy)
            # test case Initializing quantity: 71 
            # Test case Initializing byte_count: 60
            # Test case Initializing num_values: 141
            # PAIRWISE list Initializes
            # Test case Initializing : 6816

                parameters_FC16 = [ ( "quantity"
                               , fuzz_session.quantity_of_x_list_reg_cart)
                             , ( "byte_count"
                               ,fuzz_session.byte_count_test)#def lib_byte_test(self,MIN=0,SPEC=0,MAX=65535)
                            , ( "num_values"
                               ,lof.illegal_len_list())                                
                             ]
                
                # combinatorial-Quantity of Registers (0x0001 to 0x007B) vs byte_count (2 x N*)
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    pairwice_Quant_vs_byte_count=fp.loadpairsCSV(parameters_FC16,function_code)  
                    if len(pairwice_Quant_vs_byte_count)==0 :csv_NIST=False; fp.reset();return  pdu #return  pdu (not fuzz) one test and next FC

                lgr.warn('     > case 2: Combinatorial NIST-ACTS/AllPairs %s/%s (Quantity of Registers, byte_count, output_value),remain test: %d'% (csv_NIST, not csv_NIST,len(pairwice_Quant_vs_byte_count)))
                fuzz_session.quantity_of_x=pairwice_Quant_vs_byte_count[0][0]
                byte_count=pairwice_Quant_vs_byte_count[0][1]
                lgr.info('address valid: %d ..0x%02X...' % (starting_address,starting_address))
                
                if fuzz_session.quantity_of_x >123 or fuzz_session.quantity_of_x==0:
                    lgr.warn('Write quantity invalid: %d ..0x%02X..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Write quantity valid: %d ..0x%02X..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))

                #byte_count (2 x N*) N = Quantity of Registers vs output_value
                if byte_count >2*123 or byte_count==0:
                    lgr.warn('Byte count invalid (out of spec): %d , 0x%02X...' % (byte_count,byte_count))
                else :
                    if byte_count!=2*fuzz_session.quantity_of_x :lgr.warn('Byte count (not consisten Quantity): %d , 0x%02X...' % (byte_count,byte_count))
                    else:lgr.info('Byte count valid: %d , 0x%02X...' % (byte_count,byte_count))
                               
                output_value=pairwice_Quant_vs_byte_count[0][2]*[fp.output_values[0]]
                lgr.info('value: 0x%02X., num_values: %d' % (fp.output_values[0],pairwice_Quant_vs_byte_count[0][2]))
                lgr.info('Byte of data value: %d' % (2*(len(output_value))))
                fp.output_values.append(fp.output_values.pop(0))                
                
                pdu = struct.pack(">BHHB", function_code, starting_address, fuzz_session.quantity_of_x, byte_count)
                #def execute from modbus.py
                for j in  output_value:
                      fmt="H" if j>=0 else "h"
                      pdu +=struct.pack(">" + fmt,j)
                                         
                fuzz_session.starting_address=starting_address
                fuzz_session.tmp_test_list.append ([starting_address,fuzz_session.quantity_of_x,byte_count,len(output_value)])
                pairwice_Quant_vs_byte_count=np.delete(pairwice_Quant_vs_byte_count, 0, 0)
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    tcc.test_case (function_code,'Quant_vs_byte_count_vs_value',['address','quantity','byte_count','len(output_value)'],np.array(fuzz_session.tmp_test_list))
                    fp=fuzzer_pdu(); fp.reset();fuzz_session.case_FC16=True                  
                            
                break
            else :
                pass
        return pdu
    
    def is_valid_combination_f16( self,values, names, start_address=0,max_address=65535):

        """
        Quantity of Registers :2 Bytes (0x0001 to 0x007B)
        Byte Count :1 Byte (2 x N*)
        Registers Value : N* x 2 Bytes value
        ------------------------"Contr." ..rules-----#excludes them  
        lambda d: d["byte_count"] == 2*d["quantity"] and d["num_values"] == 2*d["quantity"]
        lambda d: d["num_values"] % 2 == 0 
        see, dir utils for script python
        """
        dictionary = dict( list(zip( names, values )) )

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
    

    def FC16_pairwice_Quant_byte_count(self,parameters,function_code):
        """       
        # ACTS Test Suite Generation: Wed Mar 24 12:54:09 EET 2021
        #  '*' represents don't care value 
        # Degree of interaction coverage: 2
        # Number of parameters: 3
        # Maximum number of values per parameter: 160
        # Number of configurations: 12270

        # for Allpair tools (allpairspy ) //python3 version
        # test case Initializing quantity: 71 
        # Test case Initializing byte_count: 60
        # Test case Initializing num_values: 141
        # PAIRWISE list Initializes
        # Test case Initializing : 6816

        """

        pairwise_temp =[];global csv_NIST
       
        lgr.warn("     > case 2: PAIRWISE Initializes Combinatorial(Quantity of Registers, byte_count, num of value)")
        try: #nitializing from NIST-ACTS       
            if os.path.exists(dir+"/FC0%d_pair.csv"%function_code):
                # Initializing from NIST-ACTS  read CSV file 
                with open(dir+"/FC%d_pair.csv"%function_code, 'r') as f:
                    #lgr.warn("-------Initializing from NIST-ACTS ..") 
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwise = list([[int(x) for x in line] for line in pairwise_temp])
                    pairwise.sort(key = lambda row: (row[0],row[1],row[2]) )
                    csv_NIST=True  
            #Initializing from tools AllPairs   
            else:
                    pairwise=list(AllPairs(
                    [x[1] for x in parameters],
                    filter_func=lambda values: self.is_valid_combination_f16
                        (values, [x[0] for x in parameters])))
                        
                    pairwise.sort(key = lambda row: (row[0],row[1],row[2]) ) 
                    dir="./tmpAllpair";dir = os.path.normpath(dir)           
                    # Create a folder
                    if not os.path.exists(dir):os.makedirs(dir)          
                    # read CSV file & load in  list
                    with open(dir +"/FC%d_pair.csv"%function_code,"w") as f: #write ./    not dir='./Nist-csv'  in dir='./tmpAllpair' 
                        wr = csv.writer(f);wr.writerows(pairwise)                        
                    csv_NIST=False     
        except IOError :
            lgr.exception('')

        if len (pairwise)==0:
            raise ValueError ('no data')           
        lgr.warn("     > Initializing from NIST-ACTS/AllPairs %s/%s, test: %d " % (csv_NIST, not csv_NIST,len(pairwise)))  
        return np.array(pairwise)    

class test_field_FC15(object):
    global csv_NIST,csv_heuristic 

    
    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535
        self.t1byte=256

    def fuzz_field_parameter_FC15(self,function_code,pdu,output_value=None,case_FC15=None):
        """ 
        testing one-way field in list global  fuzz_session.test_field_mult_fc
        fuzz_session.test_field_mult_fc=['address', 'quantity_of_x','byte_count','output_value', '2-way'] 
        fuzz_session.quantity_of_x_list_coil or fuzz_session.quantity_of_x_list_reg   in def Read_CSvFile
        fuzz_session.flag_boundaries=0, default
        Registers Value Combinatorial test in '2-way'  
        
        """
        tcc=test_case_coverage(); fp=fuzzer_pdu();fuzz_session.flag_boundaries=0
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:]
               
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_mult_fc[:]
            is_way('2-way')  
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)

        if test_field=='address' :                                        
            starting_address=fuzz_session.fuzz_addre_COILS[0]
            fuzz_session.fuzz_addre_COILS.append(fuzz_session.fuzz_addre_COILS.pop(0))                    #shift a list
        
        elif test_field=='quantity_of_x' :           
            quantity_of_x= fuzz_session.quantity_of_x_list_coil[0]
            fuzz_session.quantity_of_x_list_coil.append(fuzz_session.quantity_of_x_list_coil.pop(0))       #shift a list
        
        elif test_field=='byte_count' : 
            byte_count=fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))  
        
        elif test_field=='output_value' :                  
            output_value =fp.test_field_of_data(fuzz_session.output_value_test[0])   # OUTPUT byte seq
            fuzz_session.output_value_test.append(fuzz_session.output_value_test.pop(0)) 

        #2-way test   
        elif test_field=='2-way':
            return self.fuzz_field_two_way_FC15(function_code,pdu,output_value=None,case_FC15=None)   
                        
        else :
            not_exist_field(test_field)  #case not exist field  of test

        if starting_address <fuzz_session.MIN_COILS or starting_address>fuzz_session.MAX_COILS:
            lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_invalid += 1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1

        if quantity_of_x>1968 or quantity_of_x==0:
            lgr.warn('Coils quantity invalid (out of spec): %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
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

        if (byte_count >1968//8) or (byte_count==0):                   
            lgr.warn('Coils byte_count invalid (out of spec): %d ..0x%02X ..' % (byte_count,byte_count ))
            fuzz_session.field3_invalid += 1
        else :
            lgr.info('Coils byte_count valid: %d ..0x%02X ..' % (byte_count,byte_count ))
            fuzz_session.field3_valid += 1

        if (len(output_value)>0 or (len(output_value))<=246):                  #output_value=241, max N * byte for len 260 packet
            lgr.info('Output_ data len  valid: %d ..0x%02X ..' % (len(output_value),len(output_value)))
            fuzz_session.field4_valid += 1  
        else :
            lgr.warn('Output_data len invalid: %d..0x%02X ..' % (len(output_value),len(output_value)))
            fuzz_session.field4_invalid += 1          
    
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x,byte_count,len(output_value)])
        
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_COILS)  \
        or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_COILS)  \
        or (test_field=='byte_count' and byte_count==fuzz_session.l_count_byte_test)\
        or (test_field=='output_value' and fuzz_session.output_value_test[-1]==fuzz_session.l_output_value_test):
            
            if test_field=='address':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            if test_field=='byte_count':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 
            
            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_mult_fc,fuzz_session.field4_valid, fuzz_session.field4_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            tcc.test_case (function_code,test_field,fuzz_session.test_field_mult_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
                       
            #l.insert(newindex, l.pop(oldindex))  
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 : fp.reset()      
    
        fuzz_session.starting_address=starting_address
        fuzz_session.quantity_of_x=quantity_of_x
        fuzz_session.byte_count=byte_count

        pdu = struct.pack(">BHHB", function_code, starting_address, quantity_of_x,byte_count)
        pdu +=output_value 
        return   pdu

    def fuzz_field_two_way_FC15(self,function_code,pdu,output_value=None,case_FC15=None):
        
        """
        Test case Initializing
        case 1, itertools.product pairs OF COILS, and integer_boundaries for byte count coil: quantity_of_x_list
        case 2, (Combinatorial) Quantity of coils (0x0001 to 0x07B0) vs byte_count (N*) N = Quantity of out//8, vs output_value=N*x1B
        pairwice_Quant_vs_byte_count=np.array([], dtype=np.int16)
        pairwice_READ_COILS=np.array([], dtype=np.int16)
        csv_NIST=None ,csv_NIST=True CSV from NIST-ACTS  else csv_NIST=Fasle CSV from allpairs tools
        
        """
        global  lib_word_binary,pairwice_READ_COILS,pairwice_Quant_vs_byte_count,csv_NIST, csv_heuristic
        parameters=[] 
        fp=fuzzer_pdu();lof=list_of_fuzz()
        tcc=test_case_coverage()
        starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
        output_value=pdu[6:]; case_FC15=fuzz_session.case_FC15
       
        while True:
            # case 1
            if case_FC15==True: 
        
                if  pairwice_READ_COILS.size==0:
                    pairwice_READ_COILS=fp.load_pair_file (parameters,function_code)
                
                lgr.warn('     > case 1, heuristic csv/itertools.product %s/%s  for s_address vs Quantity, remain test: %d'%(csv_heuristic, not csv_heuristic, len(pairwice_READ_COILS)))
                starting_address=pairwice_READ_COILS[0][0]
                fuzz_session.quantity_of_x=pairwice_READ_COILS[0][1]
                              
                if starting_address <fuzz_session.MIN_COILS or starting_address>fuzz_session.MAX_COILS:
                    lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
                else :
                    lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
                
                if fuzz_session.quantity_of_x >1968 or fuzz_session.quantity_of_x==0:
                    lgr.warn('Coils write quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))

                else :
                    lgr.info('Coils write quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))    
                
                if (starting_address+fuzz_session.quantity_of_x) > fuzz_session.MAX_COILS :
                    lgr.warn('(address + quantity write) is invalid : %d ..0x%02X ..' % (starting_address+fuzz_session.quantity_of_x,starting_address+fuzz_session.quantity_of_x))
                    fuzz_session.flag_boundaries=1
                else :  
                    lgr.info('(address + quantity write) is valid: %d ..0x%02X ..' % (starting_address+fuzz_session.quantity_of_x,starting_address+fuzz_session.quantity_of_x))   
                    fuzz_session.flag_boundaries=0
                lgr.warn('Byte_count, consisten to Output value: %d ..0x%02X ' % (byte_count,byte_count));lgr.info('len output value: %d' % len(output_value))
                
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
          
            elif case_FC15==False:
                # byte_count,integer fuzz heuristics library  lib_interesting_256(),
                # output_value, fuzz heuristics library for illegal len frame 
                # ./tools/Allpairs_201-csv/script/case_fc15.py 
                # fuzz_session.quantity_of_x_list_coil_cart  (from def calc_quantity_fuzz) val:71
                # list_of_fuzz().lib_interesting_256()   val:60
                # lof.illegal_len_list() val:141  
                
                parameters_FC15 = [ ( "quantity"
                               , fuzz_session.quantity_of_x_list_coil_cart)
                             , ( "byte_count"
                               ,  
                               fuzz_session.output_value_test)# #lof.lib_interesting_256())
                               , ( "output_value" #length of illegal message PDU
                               ,lof.illegal_len_list() )                                
                             ]
                #case 2 Quantity of coils (0x0001 to 0x07B0) vs byte_count (N*) vs output_value
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    
                    pairwice_Quant_vs_byte_count=fp.loadpairsCSV(parameters_FC15,function_code)  
                    if len(pairwice_Quant_vs_byte_count)==0 :csv_NIST=False; fp.reset();return  pdu #return  pdu (not fuzz) one test and next FC
                    
                lgr.warn('     > case 2: Combinatorial NIST-ACTS/AllPairs %s/%s (Quantity of coils, byte count, output value),remain test: %d'% (csv_NIST, not csv_NIST,len(pairwice_Quant_vs_byte_count)))      
                fuzz_session.quantity_of_x=pairwice_Quant_vs_byte_count[0][0]
                byte_count=pairwice_Quant_vs_byte_count[0][1]
                                
                if fuzz_session.quantity_of_x >1968 or fuzz_session.quantity_of_x==0:
                   
                    lgr.warn('Coils write quantity invalid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))
                else :
                    lgr.info('Coils write quantity valid: %d ..0x%02X ..' % (fuzz_session.quantity_of_x,fuzz_session.quantity_of_x))    
                
                #Quantity of coils (0x0001 to 0x07B0) vs byte_count (N*) N = Quantity of out//8, vs output_value=N*x1B
                if (byte_count >1968//8) or (byte_count==0):
                    
                    lgr.warn('Coils byte count invalid (out of spec): %d ..0x%02X ..' % (byte_count,byte_count ))
                else :
                    if (byte_count!=fuzz_session.quantity_of_x//8):lgr.warn('Coils byte count (not consisten Quantity): %d , 0x%02X...' % (byte_count,byte_count))
                    
                    else :lgr.info('Coils byte count valid: %d ..0x%02X ..' % (byte_count,byte_count )) 
                
                lgr.info('value: 0x%02X.. Out values : %d' % (fp.output_values[0],pairwice_Quant_vs_byte_count[0][2]))
                output_value=pairwice_Quant_vs_byte_count[0][2]*[fp.output_values[0]]
                pdu = struct.pack(">BHHB", function_code, starting_address, fuzz_session.quantity_of_x,byte_count)
                
                for j in output_value :
                    if 0<=fp.output_values[0]<=255:
                        pdu +=struct.pack(">B",j)
                    else:
                        fmt="H" if j>=0 else "h"
                        pdu +=struct.pack(">" + fmt,j)
                          
                fp.output_values.append(fp.output_values.pop(0))         
                fuzz_session.starting_address=starting_address 
                fuzz_session.tmp_test_list.append ([starting_address,fuzz_session.quantity_of_x,byte_count,pairwice_Quant_vs_byte_count[0][2]])              
                pairwice_Quant_vs_byte_count=np.delete(pairwice_Quant_vs_byte_count, 0, 0)
                
                if  len(pairwice_Quant_vs_byte_count)==0 :
                    tcc.test_case (function_code,'Quant_vs_byte_count_vs_value',['address', 'quantity_of_x','byte_count','output_value'],np.array(fuzz_session.tmp_test_list))                   
                    fuzz_session.case_FC15=True
                    fp.reset() 
                                                                                 
                break
            else :
                pass
        
        return pdu 

    
    def FC15_pairwice_Quant_byte_count(self,parameters, function_code,dir='./Nist-csv'):
        
        """
        # ACTS Test Suite Generation: Thu Jul 01 10:43:55 EEST 2021
        #  '*' represents don't care value 
        # Degree of interaction coverage: 2
        # Number of parameters: 3
        # Maximum number of values per parameter: 132
        # Number of configurations: 13376
        # quan,byte_count,Out_value

        # for All pair tools /use less value from NIST-ACTS 
        # Test case Initializing quantity: 71
        # Test case Initializing byte_count: 60
        # Test case Initializing num_values: 141
        # PAIRWISE list Initializes
        # Test case Initializing : 9967 
        """    

        global csv_NIST
        lgr.warn("     > case 2: Pairwise  Initializes Combinatorial (Quantity of coils, byte count, output value)")
        try:  
            if os.path.exists(dir+"/FC%d_pair.csv"%function_code):
                # read CSV file & load in  list
                with open(dir+"/FC%d_pair.csv"%function_code, 'r') as f:  
                    reader = csv.reader(f)
                    pairwise_temp = list(reader)
                    #convert all elements to init
                    pairwise=list([[int(x) for x in line] for line in pairwise_temp])
                    pairwise.sort(key = lambda row: (row[0],row[1],row[2]) )
                    csv_NIST=True     
                                       
            else:
                    csv_NIST=False   
                    pairwise=list(AllPairs(
                    [x[1] for x in parameters],
                    filter_func=lambda values: self.is_valid_combination_f15(
                        values, [x[0] for x in parameters])))
                    pairwise.sort(key = lambda row: (row[0],row[1],row[2]) ) 
                    dir="./tmpAllpair";dir = os.path.normpath(dir) 
                    # Create a folder
                    if not os.path.exists(dir):os.makedirs(dir)          
                    # read CSV file & load in  list
                    with open(dir+"/FC%d_pair.csv"%function_code,"w") as f:   #write ./    not dir='./Nist-csv'  in dir='./tmpAllpair' 
                        wr = csv.writer(f)
                        wr.writerows(pairwise)
        except IOError :
            lgr.exception('')

        if not pairwise:
            raise ValueError ('no data')   

        lgr.warn("     > Initializing from NIST-ACTS/AllPairs %s/%s, test: %d " % (csv_NIST, not csv_NIST,len(pairwise))) 

        return np.array(pairwise)        

    def is_valid_combination_f15( self,values, names, start_address=0,max_address=65535):

        """
        Quantity of Registers :2 Bytes (0 , 1968)
        Byte Count :1 Byte 
        Coils Value : N* x 1 Bytes value
        Byte Count == Quantity of Outputs % 8 + [Quantity of Outputs // 8]
        and Outputs Value ==Quantity of Outputs//8
        [[Constraint]--#excludes them
        -- this section is also optional
        num_value!=quan//8
        byte_count != (quan%8 )+ (quan // 8)
        """
        dictionary = dict( list(zip( names, values )) )

        rules = [ 
                lambda d: d["byte_count"] == (d["quantity"]%8 + d["quantity"] // 8)                             
                ,lambda d: d["num_values"] == d["quantity"]//8                             
                ]
            
        for rule in rules:
            try:
                if rule(dictionary):
                    return False
            except KeyError: pass
        return True


class test_field_FC06(object):
 
    def __init__(self): 
        
        """
        
        """ 
        self.t2byte=65535

    
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
            is_way('2-way') 
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)
           
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
            #case not exist field  of test
            not_exist_field(test_field)  #case not exist field  of test

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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_write_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
                        
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()    

        elif (len(pairwice_WRITE_SINGLE_REGISTER)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quantity ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu(); fp.reset()
                          
        fuzz_session.starting_address=starting_address
        fuzz_session.output_value=output_value 
        if output_value <0:return  struct.pack(">BHi", function_code, starting_address,output_value) 
        else :return  struct.pack(">BHH", function_code, starting_address,output_value)    

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
        old version

        global  pairwice_WRITE_SINGLE_REGISTER 
        lof=list_of_fuzz();lib_word=lof.lib_word_cart()

        if pairwice_WRITE_SINGLE_REGISTER.size==0 :                
            pairwice_WRITE_SINGLE_REGISTER=np.array(list(itertools.product(fuzz_session.fuzz_addre_HO_REG_cart,lib_word)) )
  
        fuzz_session.starting_address=pairwice_WRITE_SINGLE_REGISTER[0][0]                                                                         
        value=bit_field((int(pairwice_WRITE_SINGLE_REGISTER[0][1])),16,65535, "<","ascii",signed=False).render() #string            
        pairwice_WRITE_SINGLE_REGISTER=np.delete(pairwice_WRITE_SINGLE_REGISTER, 0, 0)
        return  fuzz_session.starting_address,int(value)   

        """
        
        global pairwice_WRITE_SINGLE_REGISTER,csv_heuristic;parameters=[]
        fp=fuzzer_pdu()       
        if pairwice_WRITE_SINGLE_REGISTER.size==0 : #Test case Initializing -                
            pairwice_WRITE_SINGLE_REGISTER=fp.load_pair_file (parameters,function_code)
        lgr.warn('     > heuristic csv/itertools.product %s/%s for s_address vs value, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_WRITE_SINGLE_REGISTER)-1))
        value=pairwice_WRITE_SINGLE_REGISTER[0][1]
        fuzz_session.starting_address=pairwice_WRITE_SINGLE_REGISTER[0][0]                                                                         
        pairwice_WRITE_SINGLE_REGISTER=np.delete(pairwice_WRITE_SINGLE_REGISTER, 0, 0)
        return  fuzz_session.starting_address,value   
    

class test_field_FC05(object):
 
    def __init__(self): 
        
        """
        
        """ 
        self.t2byte=65535
    
    def fuzz_field_parameter_FC05(self,function_code,pdu):
        """
         i) testing single field address and ii) output_value  - under conditions all oter field not change 
        fuzz_session.test_field_write_fc=['address', 'output_value', '2-way']
        iii) test 2-way, files ./csvtestPDU coverage case valid invalid value from address, output_value 
           
        """
        global pairwice_WRITE_SINGLE_COIL
        fuzz_session.flag_boundaries=0             
        starting_address,output_value = struct.unpack(">HH", pdu[1:5])
        tcc=test_case_coverage()
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_write_fc[:]
            is_way('2-way')  
       
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)
                 
        if test_field=='address' :                                     
            starting_address=fuzz_session.fuzz_addre_COILS[0]
            fuzz_session.fuzz_addre_COILS.append(fuzz_session.fuzz_addre_COILS.pop(0))   #shift a list
            
        elif test_field=='output_value' :
            output_value= fuzz_session.values_test[0]
            fuzz_session.values_test.append(fuzz_session.values_test.pop(0))           #shift a list
       
        elif test_field=='2-way':              
            starting_address,output_value =self.fuzz_field_two_way_FC05(function_code,pdu)
             
        else :
            not_exist_field(test_field)  #case not exist field  of test

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
        if (hex(output_value) =='0x0') or (hex(output_value)=='0xff00' ):
            lgr.info('output_value valid: %d ..0x%02X ..' % (output_value,output_value))
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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='output_value':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_write_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,fuzz_session.tmp_test_list)
            fuzz_session.tmp_test_list=[]            
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()   

        elif (len(pairwice_WRITE_SINGLE_COIL)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            #tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list),t=65535) not impl
            tcc.test_case (function_code,test_field,fuzz_session.test_field_write_fc,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu(); fp.reset()
                        
        fuzz_session.starting_address=starting_address
        fuzz_session.output_value=output_value
        if output_value <0:return  struct.pack(">BHi", function_code, starting_address,output_value)
        else :return  struct.pack(">BHH", function_code, starting_address,output_value)
    
    def fuzz_field_two_way_FC05(self,function_code,pdu):
        """
        Test case Initializing  Cartesian product
        np.array(itertools.product(a, b))
        Cartesian product of x and y array points into single array of 2D points
        directly initialize 
        x= np.array([], dtype=np.init) such x= pairwice_WRITE_SINGLE_COIL           
        x = numpy.delete(x, (0), axis=0)
        negatve integer library.The bit field a number of variable length word_binary


        global pairwice_WRITE_SINGLE_COIL 
        lof=list_of_fuzz();lib_word=lof.lib_word_cart()
       
        if  len(pairwice_WRITE_SINGLE_COIL)==0 :
            pairwice_WRITE_SINGLE_COIL=np.array(list(itertools.product(fuzz_session.fuzz_addre_COILS_cart,lib_word)))       
        fuzz_session.starting_address=pairwice_WRITE_SINGLE_COIL[0][0]
        #negatve integer library.The bit field a number of variable length word_binary                                                                           
        value=bit_field((int(pairwice_WRITE_SINGLE_COIL[0][1])),16,65535, "<","ascii",signed=False).render()   #string                                
        pairwice_WRITE_SINGLE_COIL=np.delete(pairwice_WRITE_SINGLE_COIL, 0, 0)               
        return  fuzz_session.starting_address,int(value)
        """

        global pairwice_WRITE_SINGLE_COIL,csv_heuristic;parameters=[]
        fp=fuzzer_pdu()
        #Test case Initializing - 
        if not  pairwice_WRITE_SINGLE_COIL.size:
            pairwice_WRITE_SINGLE_COIL=fp.load_pair_file (parameters,function_code)
        lgr.warn('     > heuristic csv/itertools.product %s/%s for s_address vs value, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_WRITE_SINGLE_COIL)-1))
        fuzz_session.starting_address=pairwice_WRITE_SINGLE_COIL[0][0]
        value=pairwice_WRITE_SINGLE_COIL[0][1]
        pairwice_WRITE_SINGLE_COIL=np.delete(pairwice_WRITE_SINGLE_COIL, 0, 0)               
        return  fuzz_session.starting_address,value 


class test_field_FC04(object):
 
    def __init__(self): 
        
        """
        
        """ 
        self.t2byte=65535

    def fuzz_field_parameter_FC04(self,function_code,pdu):
        """
         i)testing single field address  ii) coil quantity - under conditions all oter field not change
            fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
            calculate fuzz quantity_of_x  for FC from class list_of_fuzz
            iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /./csvtestPDU"
            iv)coverage case valid invalid value from address, quan ,and  address_and_quantity  
        """
        fuzz_session.flag_boundaries=0
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])

        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
            is_way('2-way')  
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)
                 
        if test_field=='address' :                                       
            starting_address=fuzz_session.fuzz_addre_IN_REG[0]
            fuzz_session.fuzz_addre_IN_REG.append(fuzz_session.fuzz_addre_IN_REG.pop(0))                     #shift a list
        
        elif test_field=='quantity_of_x' :
            quantity_of_x= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))           #shift a list
           
        elif test_field=='2-way':  
            starting_address,quantity_of_x=self.fuzz_field_two_way_FC04(function_code,pdu)
                   
        else :
            #lgr.info('error')
            not_exist_field(test_field)  #case not exist field  of test    
 
        if (starting_address <fuzz_session.MIN_IN_REG) or (starting_address>fuzz_session.MAX_IN_REG):
           lgr.warn('address invalid: %d ..0x%02X ..' % (starting_address,starting_address))
           fuzz_session.field1_invalid += 1
        else :
            lgr.info('address valid: %d ..0x%02X ..' % (starting_address,starting_address))
            fuzz_session.field1_valid += 1
     
        if (quantity_of_x >125 or quantity_of_x==0):
            lgr.warn('READ INPUT_REGISTERS quantity invalid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
            fuzz_session.field2_invalid += 1
        else :
            lgr.info('READ INPUT_REGISTERS quantity valid: %d ..0x%02X ..' % (quantity_of_x,quantity_of_x))
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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_test_list)
            fuzz_session.tmp_test_list=[]
            
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()     
                               
        elif (len(pairwice_READ_INPUT_REGISTERS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=self.t2byte) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu(); fp.reset()
           
        fuzz_session.starting_address=starting_address
        fuzz_session.quantity_of_x=quantity_of_x      
        return struct.pack(">BHH", function_code, starting_address,quantity_of_x)

    
    def fuzz_field_two_way_FC04(self,function_code,pdu):

        """Test case Initializing    Cartesian product or NIST-ACTS-Csv file 
           numpy arrayCartesian product
        """

        global  pairwice_READ_INPUT_REGISTERS; parameters=[]
        fp=fuzzer_pdu()
        if not  pairwice_READ_INPUT_REGISTERS.size:
            pairwice_READ_INPUT_REGISTERS=fp.load_pair_file (parameters,function_code)
        lgr.warn('     > heuristic csv/itertools.product %s/%s for s_address vs Quantity, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_READ_INPUT_REGISTERS)-1))      
        starting_address=pairwice_READ_INPUT_REGISTERS[0][0]
        quantity_of_x=pairwice_READ_INPUT_REGISTERS[0][1]            
        pairwice_READ_INPUT_REGISTERS=np.delete(pairwice_READ_INPUT_REGISTERS, 0, 0)
        return starting_address,quantity_of_x


class test_field_FC03(object):
 
    def __init__(self):  
        
        """
        
        """ 
        self.t2byte=65535

    def fuzz_field_parameter_FC03(self,function_code,pdu):
        
        """  
        i) testing single field address  ii) register quantity - under conditions all other field not change
        fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
        calculate fuzz quantity_of_x  for FC from class list_of_fuzz 
        iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /./csvtestPDU"
        iv)coverage case valid invalid value from address, quan ,and  address_and_quantity
           
        """
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
            is_way('2-way')  
            
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)
                
        if test_field=='address' :                                      
            starting_address=fuzz_session.fuzz_addre_HO_REG[0]
            fuzz_session.fuzz_addre_HO_REG.append(fuzz_session.fuzz_addre_HO_REG.pop(0))                     #shift a list
        
        elif test_field=='quantity_of_x' :
            quantity_of_x= fuzz_session.quantity_of_x_list_reg[0]
            fuzz_session.quantity_of_x_list_reg.append(fuzz_session.quantity_of_x_list_reg.pop(0))           #shift a list
           
        elif test_field=='2-way':
            starting_address,quantity_of_x=self.fuzz_field_two_way_FC03(function_code,pdu)  
            
        else :
            not_exist_field(test_field)  # case not exist field  of test    
                
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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 

            if test_field=='quantity_of_x':
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte) 
            
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            #fuzz_session.fields_of_list.insert(len(fuzz_session.fields_of_list)+1,fuzz_session.fields_of_list.pop(0)) #rotate
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()    

        elif (len(pairwice_READ_HOLDING_REGISTERS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=self.t2byte) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu(); fp.reset()
           
        fuzz_session.starting_address=starting_address;  fuzz_session.quantity_of_x=quantity_of_x 
        return   struct.pack(">BHH", function_code, starting_address, quantity_of_x)    


    def fuzz_field_two_way_FC03(self,function_code,pdu):       
        """
        Test case Initializing  Cartesian product or NIST-ACTS-Csv file 
        numpy array pairwice_READ_HOLDING_REGISTERS
        """

        global  pairwice_READ_HOLDING_REGISTERS
        parameters=[]
        fp=fuzzer_pdu()

        if not  pairwice_READ_HOLDING_REGISTERS.size:
            pairwice_READ_HOLDING_REGISTERS=fp.load_pair_file (parameters,function_code)
        lgr.warn('     > heuristic csv/itertools.product %s/%s for s_address vs Quantity, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_READ_HOLDING_REGISTERS)-1))
        
        starting_address=pairwice_READ_HOLDING_REGISTERS[0][0]
        quantity_of_x=pairwice_READ_HOLDING_REGISTERS[0][1]
        pairwice_READ_HOLDING_REGISTERS=np.delete(pairwice_READ_HOLDING_REGISTERS, 0, 0)

        return starting_address,quantity_of_x
    

class test_field_FC02(object):
    
    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535
    
    def fuzz_field_parameter_FC02(self,function_code,pdu):

        """ 
        i) testing single field address  ii) Discrete inputs quantity - under conditions all oter field not change
        fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
        calculate fuzz value quantity_of_x, address  from class -list_of_fuzz
        iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /./csvtestPDU"
        iv)coverage case valid invalid value from address, quan ,and  address_and_quantity              
        """
        tcc=test_case_coverage()
        starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        test_field = fuzz_session.test_field_read_fc[0]
       
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
            is_way('2-way')    
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r ' % test_field)
           
        if test_field=='address' :                                                     
            starting_address=fuzz_session.fuzz_addre_DIS_IN[0]
            fuzz_session.fuzz_addre_DIS_IN.append(fuzz_session.fuzz_addre_DIS_IN.pop(0))                      #shift a list
        
        elif test_field=='quantity_of_x' :            
            quantity_of_x= fuzz_session.quantity_of_x_list_coil[0]
            fuzz_session.quantity_of_x_list_coil.append(fuzz_session.quantity_of_x_list_coil.pop(0))           #shift a list
          
        elif test_field=='2-way':  
            starting_address,quantity_of_x=self.fuzz_field_two_way_FC02(function_code,pdu)
        
        else :#from utils_b, case not exist field  of test
            not_exist_field(test_field)  #case not exist field  of test

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
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)            
                                          
            if test_field=='quantity_of_x':                                                        
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)            
        
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]             
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()      
        
        elif (len(pairwice_READ_DISCRETE_INPUTS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=self.t2byte)           
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu(); fp.reset()
                              
        fuzz_session.starting_address=starting_address;fuzz_session.quantity_of_x=quantity_of_x                       
        return struct.pack(">BHH", function_code, starting_address, quantity_of_x)  

    
    def fuzz_field_two_way_FC02(self,function_code,pdu):
        """
        Test case Initializing   -Csv file rom heuristic class findPairs
        pairwice_READ_DISCRETE_INPUTS numpy array
        """
        
        global  pairwice_READ_DISCRETE_INPUTS ;parameters=[]; fp=fuzzer_pdu()

        if not  pairwice_READ_DISCRETE_INPUTS.size:
            pairwice_READ_DISCRETE_INPUTS=fp.load_pair_file (parameters,function_code)
        lgr.warn('     > heuristic csv/itertools.product %s/%s for s_address vs Quantity, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_READ_DISCRETE_INPUTS)-1))
                
        starting_address=pairwice_READ_DISCRETE_INPUTS[0][0]       
        quantity_of_x=pairwice_READ_DISCRETE_INPUTS[0][1]
        pairwice_READ_DISCRETE_INPUTS=np.delete(pairwice_READ_DISCRETE_INPUTS, 0, 0)        
        return starting_address,quantity_of_x    
    
    
class test_field_FC01(object):
    

    def __init__(self): 
        
        """
        
        """
        self.t2byte=65535


    def fuzz_field_parameter_FC01(self,function_code,pdu):

        """ i) testing single field address  ii) coil quantity - under conditions all oter field not change
            fuzz_session.test_field_read_fc=['address', 'quantity_of_x', '2-way']
            calculate fuzz quantity_of_x  for FC from class list_of_fuzz   
            pack bits in bytes
            byte_count = quantity_of_x // 8 -if (quantity_of_x % 8) > 0: byte_count += 1 
            iii) test 2-way, files csv file from heuristic class findPairs for  FC for interest  value  include in folder root mtf /./csvtestPDU
            iv)coverage case valid invalid value from address, quan ,and  address_and_quantity 
            case and coverage for field no:
            e.g
            address        2000       63536      100.00
            quantity_of_x  2000       63536      100.00
           
           self.reset() intialize temp list and flag
           fuzz_session.test_flag_parameter_PDU=False    end test parameter_PDU
           fuzz_session.test_flag_fc=True                disable/enable test FC for next FC
           fuzz_session.flag_reguest=False               Stop reguest /and fuzzer  
        """
        tcc=test_case_coverage();starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
        # one function
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_field_read_fc[:]
            is_way('2-way')  
            
        test_field = fuzz_session.fields_of_list[0]                                   
        lgr.info('testing field: % r' % test_field)
        
        if test_field=='address' :                                                    
            starting_address=fuzz_session.fuzz_addre_COILS[0]
            fuzz_session.fuzz_addre_COILS.append(fuzz_session.fuzz_addre_COILS.pop(0))                        #shift a list
        
        elif test_field=='quantity_of_x' :          
            quantity_of_x= fuzz_session.quantity_of_x_list_coil[0]
            fuzz_session.quantity_of_x_list_coil.append(fuzz_session.quantity_of_x_list_coil.pop(0))           #shift a list
        
        elif test_field=='2-way':  
            starting_address,quantity_of_x= self.fuzz_field_two_way_FC01(function_code,pdu)
            
        else :
            not_exist_field(test_field)  #case not exist field  of test    

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
            fuzz_session.address_quantity_invalid += 1; fuzz_session.flag_boundaries=1             
        else :  
            lgr.info('(address + quantity) is  valid: %d ..0x%02X ..' % (starting_address+quantity_of_x,starting_address+quantity_of_x))
            fuzz_session.address_quantity_valid += 1;fuzz_session.flag_boundaries=0 
            
        # e.g l.append([1,2,3])-create a list of lists
        fuzz_session.tmp_test_list.append ([starting_address,quantity_of_x])
        #check -fuzz_session.l_fuzz_addre_COILS,fuzz_session.l_quantity_of_COILS last item of list
        if  (test_field=='address' and starting_address==fuzz_session.l_fuzz_addre_COILS) or (test_field=='quantity_of_x' and quantity_of_x==fuzz_session.l_quantity_of_COILS):
            
            if test_field=='address': 
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)         
               
            if test_field=='quantity_of_x':                             
                tcc.Coverage (function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t2byte)         
           
            #l.insert(newindex, l.pop(oldindex))
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu(); fp.reset()            
                               
        elif (len(pairwice_READ_COILS)==0 and test_field=='2-way'):
            #add case valid invalid value from address, quan ,and  address_and_quantity
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.address_quantity_valid, fuzz_session.address_quantity_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_field_read_fc,fuzz_session.tmp_list_of_case,t=self.t2byte) 
            tcc.test_case (function_code,test_field,fuzz_session.test_field_read_fc,np.array(fuzz_session.tmp_test_list))
            #intialize temp list of list for coverage  and flag
            fp=fuzzer_pdu(); fp.reset()
           
           
        fuzz_session.starting_address=starting_address;fuzz_session.quantity_of_x=quantity_of_x        
        return   struct.pack(">BHH", function_code, starting_address, quantity_of_x)


    def fuzz_field_two_way_FC01(self,function_code,pdu):

        """pairs OF COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
           integer_boundaries for byte count REG: quantity_of_x_list
           use csv file from heuristic class findPairs for  FC for interest  value or cartesian product use min.max address (reconise) and interest value from 
           return pairwice_READ_COILS is np array
           parameters= [ ( "address"
           fuzz_session.fuzz_addre_COILS_cart)
          , ( "quantity"
           , fuzz_session.quantity_of_x_list_coil_cart)
             ]
        """
        global pairwice_READ_COILS,csv_heuristic;parameters=[]
        fp=fuzzer_pdu()
        #Test case Initializing - 
        if not  pairwice_READ_COILS.size:
            pairwice_READ_COILS=fp.load_pair_file (parameters,function_code)
        lgr.warn('     > heuristic csv/itertools.product %s/%s for s_address vs Quantity, remain test: %d'%(csv_heuristic, not csv_heuristic,len(pairwice_READ_COILS)-1))
        starting_address=pairwice_READ_COILS[0][0]
        quantity_of_x=pairwice_READ_COILS[0][1]            
        pairwice_READ_COILS=np.delete(pairwice_READ_COILS, 0, 0)
        return starting_address,quantity_of_x

#----------------------------------------------------------------------------------------------------#            
#   test for FC 43   testing one-way, 
#   PAIRWISE test for FC43 -create of NIST-ACST as FC43_pair_test.csv-defaults
#   or create of tools AllPairs 2.0.1 from allpairspy
#   fuzz_session.test_FC43=['mei_type','read_code','object_id','2-way' ]      
#----------------------------------------------------------------------------------------------------# 

class test_field_FC43(object):
    global pairwice_file,pairwice_Read_device_Ident

    def __init__(self,flag=None): 
        
        """
       
        """
        self.t1byte=256  
        self.t2byte=65535
        
        
    #@staticmethod
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
        dict_operation_,
        
        """ 
        
        fuzz_session.flag_boundaries=0
        tcc=test_case_coverage()             
        mei_type,read_code,object_id = struct.unpack(">BBB", pdu[1:5])        
        
        if len(fuzz_session.fields_of_list) == 0:
            fuzz_session.fields_of_list=fuzz_session.test_FC43[:]
            
            is_way('2-way')  #Choice single or pairwise test of fields -
          
        test_field = fuzz_session.fields_of_list[0]                                 
        lgr.info('testing field: % r ' % test_field)
                                           
        if test_field=='mei_type' :                                                     
            mei_type=fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))           #shift a list

        elif test_field=='read_code' :
            read_code=fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))           #shift a list
            
        elif test_field=='object_id' :
            object_id =fuzz_session.byte_count_test[0]
            fuzz_session.byte_count_test.append(fuzz_session.byte_count_test.pop(0))       
            
        elif test_field=='2-way':  
            mei_type,read_code,object_id=self.fuzz_field_two_way_FC43(function_code,pdu)

        else :
            not_exist_field(test_field)  # case not exist field  of test

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
        if  (mei_type==fuzz_session.l_byte_count and test_field=='mei_type') or (read_code==fuzz_session.l_byte_count and test_field=='read_code' ) \
            or (object_id==fuzz_session.l_byte_count and test_field=='object_id')  :
            
            if test_field=='mei_type':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC43,fuzz_session.field1_valid, fuzz_session.field1_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 

            if test_field=='read_code':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC43,fuzz_session.field2_valid, fuzz_session.field2_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 
            
            if test_field=='object_id':
                tcc.Coverage (function_code,test_field,fuzz_session.test_FC43,fuzz_session.field3_valid, fuzz_session.field3_invalid,np.array(fuzz_session.tmp_test_list),t=self.t1byte) 
           
            tcc.test_case (function_code,test_field,fuzz_session.test_FC43,np.array(fuzz_session.tmp_test_list))
            fuzz_session.tmp_test_list=[]
            #l.insert(newindex, l.pop(oldindex))
            fuzz_session.fields_of_list.pop(0)
            if  fuzz_session.way==1 and len(fuzz_session.fields_of_list)==0 :fp=fuzzer_pdu();fp.reset()   
        
        elif (len(pairwice_Read_device_Ident)==0 and test_field=='2-way'):
            #map(lambda x, y: x.append(y), listdata, list_o_lists)
            fuzz_session.tmp_list_of_case.append([fuzz_session.field1_valid,fuzz_session.field1_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field2_valid,fuzz_session.field2_invalid])
            fuzz_session.tmp_list_of_case.append([fuzz_session.field3_valid,fuzz_session.field3_invalid])
            tcc.Coverage_of_pair(function_code,test_field,fuzz_session.test_FC43,fuzz_session.tmp_list_of_case,t=self.t2byte) 
            tcc.test_case (function_code,test_field,fuzz_session.test_FC43,np.array(fuzz_session.tmp_test_list))
            fp=fuzzer_pdu();fp.reset()
           
        fuzz_session.mei_type=mei_type
        fuzz_session.read_code=read_code
        fuzz_session.object_id=object_id
        return  struct.pack(">BBBB", function_code,mei_type,read_code,object_id)
   
    def fuzz_field_two_way_FC43(self,function_code,pdu):
        """  
        Read Device Information Fc=43 (0x2B) MEI_sub_function_code  13/14
        function_code = 0x2b, sub_function_code = 0x0e --dec14
        pairs field of MEI Type",Read Dev Id code"and Object_Id
        0x00 <= self.object_id <= 0xff) and  (0x00 <= self.read_code <= 0x04), 
        Extended: , range(0x80, i)

        PAIRWISE test for FC43  -create of NIST-ACST as FC43_pair_test.csv-defaults
            or create of tools AllPairs 2.0.1 from allpairspy 
        ACTS Test Suite Generation: Wed Mar 18 20:43:59 EET 2020// -CSV FILE
        *' represents don't care value -extend test all pairwise for mei_type=x0E
        and some test for mei_type=0,1,2,..127,128..254..255
        Test case Initializing
        Test case Initializing  mei_type: 0,255,13,14 ..28..254..255
        Test case Initializing Read Dev Id code: 60 case
        Test case Initializing Object_Id: 60 case

        all case mei_type:14 and compinatorial Read Dev Id code and Object_Id, ex 60 test with
        coverage single test with Read Dev Id code:1
        and 100 case for mei_type:13, 0, 255 and compinatorial Read Dev Id code and Object_Id:
        Test case Initializing : ..3880
        ./Nist-csv ..
        ......
        for All pair tools /**allpairspy** forked from `bayandin/allpairs <https://github.com/bayandin/allpairs>`
        all case mei_type:0,255,13,14 and compinatorial Read Dev Id code and Object_Id
        Test case Initializing  mei_type: 0,255,13,14
        Test case Initializing Read Dev Id code: 60
        Test case Initializing Object_Id: 60
        PAIRWISE list Initializes
        Test case Initializing : 822
        
        """
        global  pairwice_Read_device_Ident,csv_NIST;fp=fuzzer_pdu()
        
        parameters_FC43= [ ( "MEI Type"
                       , [0,255,13,14])
                     , ( "Read Dev Id code"
                       ,  fuzz_session.output_value_test)#list_of_fuzz().lib_interesting_256())
                     , ( "Object_Id"
                        ,fuzz_session.output_value_test)
                     ]

        if  len(pairwice_Read_device_Ident)==0 :
            pairwice_Read_device_Ident=fp.loadpairsCSV(parameters_FC43,function_code)
        lgr.warn('     > Combinatorial NIST-ACTS/AllPairs %s/%s (MEI Type,Read Dev,Object_Id),remain test: %d'% (csv_NIST, not csv_NIST,len(pairwice_Read_device_Ident)-1))        

        mei_type=pairwice_Read_device_Ident[0][0]        
        read_code=pairwice_Read_device_Ident[0][1]                
        object_id=pairwice_Read_device_Ident[0][2]
        pairwice_Read_device_Ident=np.delete(pairwice_Read_device_Ident, 0, 0)
           
        return   mei_type,read_code,object_id
    

    def is_valid_combination_f43( self,values, names,start_address=None,max_address=None):

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
        dictionary = dict( list(zip( names, values )) )

        rules = [ 
                lambda d: 1 == d["Read Dev Id code"] and 0<=d["Object_Id"]<3 
                ,lambda d: 2 == d["Read Dev Id code"] and 3<=d["Object_Id"]<129
                ,lambda d: 3 == d["Read Dev Id code"] and 128<d["Object_Id"]<256
                   
                ]
            
        for rule in rules:
            try:
                if rule(dictionary):
                    return False
            except KeyError: pass
        return True
