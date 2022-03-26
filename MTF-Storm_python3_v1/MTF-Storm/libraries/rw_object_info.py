#!/usr/bin/env python
# -*- coding: utf-8 -*-

import csv
import logging
import logging.handlers as handlers
import fuzz_session

from .pairs_address import pairs_address_qua #from module 
from  .library_calc_value import list_of_fuzz
from basetest.test_format import test_illegal_PDU
from defines import *
lgr=logging.getLogger('') # create logger- 

#-----------------------------------------------------------------------------------------------------------------------
# Read csv file for config  fuzzer/calc fuzz address list from class list_of_fuzz 
# np array for test address vs quantity in FC01, FC02, FC03 ..call class  pairsfind=pairs_address_qua() (libraries)
# defines.py
# MAX_QUANT_COIL_FC01=1968
# MAX_QUANT_COIL_FC15=2000
# MAX_QUANT_REG_FC03=121
# MAX_QUANT_REG_FC16=125
# MAX_OF_WORD16=65535
# MAX_OF_WORD8=255
# MIN_OF_WORD=0
# MAX_REF_TYPE_File_record=6
# MIN_B_COUNT_File_record=7
# MAX_RECORD_NUM_File_record=9999
# MAX_B_COUNT_File_record=245
# MAX_FILE_NUM_File_record=10
# MAX_REC_LEN_File_record=122
#-----------------------------------------------------------------------------------------------------------------------
class Rw_object_info(list_of_fuzz):


    def __init__(self,b=10,step_of_b=2,last_elements=-1):
        
        self.FCValues0 = []                                             
        self.FCValues1 = []
        self.IN_REG=[] 
        self.COILS=[]
        self.DIS_IN =[]
        self.HO_REG=[]

        self.b=b
        self.step_of_b=step_of_b
        self.last_elements=last_elements 

        self.MIN_OF_WORD=MIN_OF_WORD      #0
        self.MAX_OF_WORD16=MAX_OF_WORD16  #65535
        self.MAX_OF_WORD8=MAX_OF_WORD8    #255
        self.MAX_QUANT_COIL_FC01=MAX_QUANT_COIL_FC01
        self.MAX_QUANT_COIL_FC15=MAX_QUANT_COIL_FC15
        self.MAX_QUANT_REG_FC23=MAX_QUANT_REG_FC23
        self.MAX_QUANT_REG_FC16=MAX_QUANT_REG_FC16
        self.MAX_REF_TYPE_File_record=MAX_REF_TYPE_File_record
        self.MIN_B_COUNT_File_record=MIN_B_COUNT_File_record
        self.MAX_B_COUNT_File_record=MAX_B_COUNT_File_record
        self.MAX_RECORD_NUM_File_record=MAX_RECORD_NUM_File_record
        self.MAX_FILE_NUM_File_record=MAX_FILE_NUM_File_record
        self.MAX_REC_LEN_File_record=MAX_REC_LEN_File_record


    def Read_CSvFile(self):
        lof=list_of_fuzz()
        #import from pairs_address import * /separation script , class pairs_address_qua
        pairsfind=pairs_address_qua() #libraries
        tip=test_illegal_PDU()

        try :
                values = csv.reader(open('search.csv', 'r'), delimiter='\t')
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
                fuzz_session.FCmergedlist = [_f for _f in fuzz_session.FCmergedlist if _f]
                fuzz_session.FCmergedlist = list(set(fuzz_session.FCmergedlist))                    
                
                self.IN_REG = [_f for _f in self.IN_REG if _f];self.COILS = [_f for _f in self.COILS if _f];
                self.DIS_IN= [_f for _f in self.DIS_IN if _f]; self.HO_REG = [_f for _f in self.HO_REG if _f]
                                                            
                #convert all strings in a list to ints and sort list
                fuzz_session.FCmergedlist = [int(i) for i in fuzz_session.FCmergedlist]
                self.IN_REG = [int(i) for i in self.IN_REG]
                self.COILS = [int(i) for i in self.COILS]
                self.DIS_IN = [int(i) for i in self.DIS_IN]
                self.HO_REG = [int(i) for i in self.HO_REG]  
               
                fuzz_session.FCmergedlist.sort()
                #for all list min//max address                        
                fuzz_session.MIN_COILS =min(self.COILS );fuzz_session.MAX_COILS =max(self.COILS )           
                fuzz_session.MIN_IN_REG=min(self.IN_REG);fuzz_session.MAX_IN_REG=max(self.IN_REG)           
                fuzz_session.MIN_DIS_IN=min(self.DIS_IN); fuzz_session.MAX_DIS_IN=max(self.DIS_IN)           
                fuzz_session.MIN_HO_REG=min(self.HO_REG);fuzz_session.MAX_HO_REG=max(self.HO_REG)
                                                
                #calculate fuzz  address for FC from class list_of_fuzz 
                #b is bountery of value
                self.calc_address_fuzz()              
                
                #calculate fuzz quantity_and output_value  for FC from class list_of_fuzz
                self.calc_quantity_fuzz()

                #use fuzzing MBAP/from class list_of_fuzz
                self.calc_MBAP_fuzz()

                #FC 20, 21, calculate fuzz byte count, address and files for FC from class list_of_fuzz 
                self.calc_filerecord_fuzz()

                #test for interesting value field FC15, FC16
                #library for diagnostics_(FC=8) for test_field:sub-function 
                self.other_library ()

                #len of list address ,len of library for test field quantity and output_value
                self.len_of_library_value_test_ADDR_QUAN()

                #last element of a list use in test PDU field 1-way, 2-way for flag with end test
                #self.last_elements=-1
                self.calc_last_elements ()

                #READ_COILS = 1,READ_DISCRETE_INPUTS = 2,READ_HOLDING_REGISTERS = 3,READ_INPUT_REGISTERS = 4
                #fuzz testing  a field of PDU Modbus protocol, dir="tmp/" save dir .csv for test address vs quantity in FC01, FC02, FC03 ..
                #return np.array(pairwise)
                self.pair_array_addr_quan ()

                # log print set configuration           
                self.print_info_test()

        except IOError:
                lgr.error('No such file or directory: search.csv')
                sys.exit(1)

    def print_info_test(self):

        """
        Configuration (value test, total test) for function, MBAP test,
        set configuration quantity_of_x_list, address for single  and 2-way in PDU fields
        configuration for fuzzing not specification message len and Dumplicate
        """
        tip=test_illegal_PDU();lof=list_of_fuzz()
        lgr.info('')
        lgr.info('     > Configuration Read from CSV')
        lgr.info('FC support (FCs): %s' %fuzz_session.FCmergedlist)
        lgr.info('')            
        lgr.info('COILS support: %s' %self.COILS);lgr.info('DIS_IN support: %s' %self.DIS_IN)     
        lgr.info('HO_REG support: %s' % self.HO_REG) ; lgr.info('IN_REG_support: %s' %self.IN_REG)         
        
        #set configuration address  MAX /MIN               
        self.recon_address_MAX_MIN()
       
        #Configuration (value test, total test) for function 20,21,22     
        self.value_test_FC_file_records()

        #set Configuration value for MBAP test
        self.config_MBAP()

        #set configuration quantity_of_x_list, address for single  and 2-way in PDU fields
        self.config_test_fields ()

        #configuration for fuzzing not specification message len and Dumplicate
        #class interesting byte and and random/smart characters
        self.config_test_format()

    def calc_address_fuzz(self):

        """
        calculate fuzz  address for FC from class list_of_fuzz 
        b is bountery of value

        """
        lof=list_of_fuzz()
        fuzz_session.fuzz_addre_COILS=lof.list_of_address(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS)
        fuzz_session.fuzz_addre_COILS_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_COILS,fuzz_session.MAX_COILS,self.b)           
        fuzz_session.fuzz_addre_DIS_IN=lof.list_of_address(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN)
        fuzz_session.fuzz_addre_DIS_IN_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_DIS_IN,fuzz_session.MAX_DIS_IN,self.b)            
        fuzz_session.fuzz_addre_IN_REG=lof.list_of_address(fuzz_session.MIN_IN_REG,fuzz_session.MAX_IN_REG)
        fuzz_session.fuzz_addre_IN_REG_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_IN_REG,fuzz_session.MAX_IN_REG,self.b)
        fuzz_session.fuzz_addre_HO_REG=lof.list_of_address(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG)
        fuzz_session.fuzz_addre_HO_REG_cart=lof.list_address_for_cart_prod(fuzz_session.MIN_HO_REG,fuzz_session.MAX_HO_REG,self.b)
        
    def calc_quantity_fuzz(self):

        """
        calculate fuzz quantity_and output_value  for FC from class list_of_fuzz
        def list_of_quantity(self,MIN,MAX) : 
        from class list_of_fuzz for use cartesian product with a limited number of interests,
        use fuzzing parameter PDU-use in test FC 16, F23, (quantity register 121,123, 125 +-10)
        list_quantity_for_cart_prod(MIN,MAX,b), b +-
        def list_quantity_for_cart_prod(self,MIN,MAX,b) 

        """
        
        lof=list_of_fuzz()
        
        fuzz_session.quantity_of_x_list_coil=lof.list_of_quantity(self.MAX_QUANT_COIL_FC01,self.MAX_QUANT_COIL_FC15)
        fuzz_session.quantity_of_x_list_reg=lof.list_of_quantity(self.MAX_QUANT_REG_FC23,self.MAX_QUANT_REG_FC16)
        fuzz_session.quantity_of_x_list_reg_cart=lof.list_quantity_for_cart_prod(self.MAX_QUANT_REG_FC23,self.MAX_QUANT_REG_FC16,self.step_of_b)
        fuzz_session.quantity_of_x_list_coil_cart=lof.list_quantity_for_cart_prod(self.MAX_QUANT_COIL_FC01,self.MAX_QUANT_COIL_FC15,self.step_of_b)
    

    def calc_MBAP_fuzz(self):
        """
        use fuzzing MBAP/from class list_of_fuzz

        """
        lof=list_of_fuzz()  #libraries 
        fuzz_session.lib_of_MBAP_transid=lof.lib_of_MBAP_transid(self.MIN_OF_WORD,self.MAX_OF_WORD16) #def lib_of_MBAP_transid(self,MIN,MAX) :
        fuzz_session.lib_of_MBAP_protocol=lof.lib_of_MBAP_protocol((self.MAX_OF_WORD16+1)//2,self.MAX_OF_WORD16) #def lib_of_MBAP_protocol(self,MIN,MAX)
        fuzz_session.lib_of_MBAP_Unit_id=lof.lib_byte_test(self.MIN_OF_WORD,self.MAX_OF_WORD8,self.MAX_OF_WORD8+1) #lib_byte_test(self,MIN=0,SPEC=0,MAX=65535):
        fuzz_session.lib_of_MBAP_length=lof.lib_of_MBAP_length() 

    def other_library (self):
        """
        32-bit only sin negative -list32bit
        """ 
        lof=list_of_fuzz()
        list16bit=lof.lib_word();list32bit=lof.lib_word32()

        #test for interesting value field FC15, FC16
        fuzz_session.output_value_test=lof.lib_interesting_256()
        
        #test single (1-way) in FC05, FC06, FC22, FC08 /test -
        fuzz_session.values_test=list32bit+list16bit

        #def lib_byte_test(self,MIN=0,SPEC=0,MAX=65535): 
        fuzz_session.byte_count_test=lof.lib_byte_test(self.MIN_OF_WORD,self.MAX_OF_WORD8,self.MAX_OF_WORD8+1)

        #library for diagnostics_(FC=8) for test_field:sub-function -test
        fuzz_session.lib_test_sub_diag=lof.lib_test_sub_diag()
        
    def calc_filerecord_fuzz(self):
        """
        FC 20, 21, calculate fuzz byte count, address and files for FC from class list_of_fuzz 
        one_byte_test=29 value, apply in test pairwise par((0,*,255),(0,*,65535))
        two_byte_test= value,record_length, FC 21, 2x122 MAX valid packet
        lib_byte_test(self,MIN=0,SPEC=0,MAX=65535)

        """
        lof=list_of_fuzz()
        
        fuzz_session.count_byte_test=lof.lib_byte_test(self.MIN_B_COUNT_File_record,self.MAX_B_COUNT_File_record,self.MAX_OF_WORD8+1)
        fuzz_session.ref_byte_test=lof.lib_byte_test(self.MIN_OF_WORD,self.MAX_REF_TYPE_File_record,self.MAX_OF_WORD8+1)
        fuzz_session.fuzz_files_rum=lof.lib_byte_test(self.MIN_OF_WORD,self.MAX_FILE_NUM_File_record,self.MAX_OF_WORD16) 
        fuzz_session.fuzz_files_rec=lof.lib_byte_test(self.MIN_OF_WORD,self.MAX_RECORD_NUM_File_record,self.MAX_OF_WORD16)       
        fuzz_session.record_length=lof.lib_byte_test(self.MIN_OF_WORD,self.MAX_REC_LEN_File_record,self.MAX_OF_WORD16)
        

    def len_of_library_value_test_ADDR_QUAN(self):
       
        """
        len of list address ,len of library for test field quantity and output_value
        """
        fuzz_session.len_of_COILS=len(fuzz_session.fuzz_addre_COILS)
        fuzz_session.len_of_DIS_IN=len(fuzz_session.fuzz_addre_DIS_IN)
        fuzz_session.len_of_HO_REG=len(fuzz_session.fuzz_addre_IN_REG)
        fuzz_session.len_of_IN_REG=len(fuzz_session.fuzz_addre_HO_REG)       
        fuzz_session.len_quantity_of_COILS=len(fuzz_session.quantity_of_x_list_coil)
        fuzz_session.len_quantity_of_REG=len(fuzz_session.quantity_of_x_list_reg)

    def calc_last_elements (self):

        """
        last element of a list use in test PDU field 1-way, 2-way for flag with end test
        self.last_elements=-1
        """
        fuzz_session.l_fuzz_addre_COILS=fuzz_session.fuzz_addre_COILS[self.last_elements]
        fuzz_session.l_fuzz_addre_DIS_IN=fuzz_session.fuzz_addre_DIS_IN[self.last_elements]
        fuzz_session.l_fuzz_addre_HO_REG=fuzz_session.fuzz_addre_HO_REG[self.last_elements]
        fuzz_session.l_fuzz_addre_IN_REG=fuzz_session.fuzz_addre_IN_REG[self.last_elements]
        fuzz_session.l_quantity_of_COILS=fuzz_session.quantity_of_x_list_coil[self.last_elements]
        fuzz_session.l_quantity_of_REG=fuzz_session.quantity_of_x_list_reg[self.last_elements]
        fuzz_session.l_output_value=fuzz_session.values_test[self.last_elements]
        fuzz_session.l_output_value_test=fuzz_session.output_value_test[self.last_elements]
        fuzz_session.l_byte_count=fuzz_session.byte_count_test[self.last_elements]
        fuzz_session.l_item_test_sub_diag=fuzz_session.lib_test_sub_diag[-1]

        #last element of a list, use in test MBAP, case not duplicates elements/ is short list
        fuzz_session.l_lib_of_MBAP_transid=fuzz_session.lib_of_MBAP_transid[self.last_elements]
        fuzz_session.l_lib_of_MBAP_protocol=fuzz_session.lib_of_MBAP_protocol[self.last_elements]
        fuzz_session.l_lib_of_MBAP_Unit_id=fuzz_session.lib_of_MBAP_Unit_id[self.last_elements]
        fuzz_session.l_lib_MBAP_length=fuzz_session.lib_of_MBAP_length[self.last_elements]
       
        #last element of a list use FC 20,21
        fuzz_session.l_lib_of_files_rum=fuzz_session.fuzz_files_rum[self.last_elements]
        fuzz_session.l_lib_of_files_rec=fuzz_session.fuzz_files_rec[self.last_elements]
        fuzz_session.l_count_byte_test=fuzz_session.count_byte_test[self.last_elements]
        fuzz_session.l_ref_byte_test=fuzz_session.ref_byte_test[self.last_elements]
        fuzz_session.l_record_length=fuzz_session.record_length[self.last_elements]
        fuzz_session.l_fuzz_files_rec=fuzz_session.fuzz_files_rec[self.last_elements]
        

    def pair_array_addr_quan (self):
        """
        call class  pairsfind=pairs_address_qua(), param  max and min address
        READ_COILS = 1,READ_DISCRETE_INPUTS = 2,READ_HOLDING_REGISTERS = 3,READ_INPUT_REGISTERS = 4
        fuzz testing  a field of PDU Modbus protocol, dir="tmp/" save dir .csv for test address vs quantity in FC01, FC02, FC03 ..
        return np.array(pairwise)
        global pairwice_READ_COILS ,pairwice_READ_HOLDING_REGISTERS ..
        """
        #import from pairs_address import * /separation script, class pairs_address_qua
        pairsfind=pairs_address_qua() #libraries
        lgr.info('')
        lgr.info("     > Set configuration pairwise test of field PDU (address vs quantity)")
        pairwice_READ_COILS=pairsfind.pair(READ_COILS,fuzz_session.fuzz_addre_COILS_cart,fuzz_session.quantity_of_x_list_coil_cart,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS )
        pairwice_READ_DISCRETE_INPUTS=pairsfind.pair(READ_DISCRETE_INPUTS,fuzz_session.fuzz_addre_IN_REG_cart,fuzz_session.quantity_of_x_list_coil_cart,fuzz_session.MAX_DIS_IN,fuzz_session.MIN_DIS_IN )
        pairwice_READ_HOLDING_REGISTERS=pairsfind.pair(READ_HOLDING_REGISTERS,fuzz_session.fuzz_addre_HO_REG_cart,fuzz_session.quantity_of_x_list_reg_cart,fuzz_session.MAX_HO_REG,fuzz_session.MIN_HO_REG)
        pairwice_READ_INPUT_REGISTERS=pairsfind.pair(READ_INPUT_REGISTERS,fuzz_session.fuzz_addre_IN_REG_cart,fuzz_session.quantity_of_x_list_reg_cart,fuzz_session.MAX_IN_REG,fuzz_session.MIN_IN_REG )
        l2=[]
        pairwice_WRITE_SINGLE_COIL=pairsfind.pair(WRITE_SINGLE_COIL,fuzz_session.fuzz_addre_COILS_cart,l2,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS )
        pairwice_WRITE_SINGLE_REGISTER=pairsfind.pair(WRITE_SINGLE_REGISTER ,fuzz_session.fuzz_addre_HO_REG_cart,l2,fuzz_session.MAX_HO_REG,fuzz_session.MIN_HO_REG)


    def recon_address_MAX_MIN(self):
        """
        log set configuration address  MAX/MIN from reconnaissance
        """
        lgr.info('')
        lgr.info('     > Set configuration address MIN/MAX')
        lgr.info('start_address READ COILS: %d' %fuzz_session.MIN_COILS )
        lgr.info('last_address READ COILS: %d' %fuzz_session.MAX_COILS )
        lgr.info('start_address READ DISCRETE_INPUTS: %d' %fuzz_session.MIN_DIS_IN)
        lgr.info('last_address READ DISCRETE INPUTS: %d' %fuzz_session.MAX_DIS_IN)
        lgr.info('start_address READ HOLDING REGISTERS: %d' %fuzz_session.MIN_HO_REG)
        lgr.info('last_address READ HOLDING REGISTERS: %d' %fuzz_session.MAX_HO_REG)
        lgr.info('start_address READ INPUT_REGISTERS: %d' %fuzz_session.MIN_IN_REG)
        lgr.info('last_address READ INPUT REGISTERS: %d' %fuzz_session.MAX_IN_REG)
        

    def value_test_FC_file_records(self):
        """
        Set Configuration (value test, total test) for FC 20,21,22 single test
        """
        lgr.info('')
        lgr.info('      > Set Configuration for FC 20,21,22 ')
        lgr.info('Total of test Byte count: %d' %len(fuzz_session.count_byte_test))
        lgr.info('Value of test Byte count: %r' %fuzz_session.count_byte_test)
        lgr.info('Total of test Reference Type: %d' %len(fuzz_session.ref_byte_test))
        lgr.info('Value of test Reference Type: %r' %fuzz_session.ref_byte_test)
        lgr.info('Start_address_records: %d' %start_address_reco)
        lgr.info('Value of test file number: %r' %fuzz_session.fuzz_files_rum)
        lgr.info('Total of test file number: %d' %len(fuzz_session.fuzz_files_rum))
        lgr.info('Value of test files records data: %r' %fuzz_session.fuzz_files_rec)
        lgr.info('Total value of test files records data: %d' %len(fuzz_session.fuzz_files_rec))
        lgr.info('Value of test records length: %r' %fuzz_session.record_length)
        lgr.info('Total value of test records length: %d' %len(fuzz_session.record_length))


    def config_MBAP(self):
        """
        log set Configuration value for MBAP singel test

        """
        lgr.info('')
        lgr.info('     > Set configuration for MBAP (single test)')
        lgr.info('Value of test  MBAP transaction: %r' %fuzz_session.lib_of_MBAP_transid)
        lgr.info('total of test  MBAP transaction: %d' %len(fuzz_session.lib_of_MBAP_transid))
        lgr.info('Value of test MBAP  protocol: %r' %fuzz_session.lib_of_MBAP_protocol)
        lgr.info('total of test  MBAP protocol: %d' %len(fuzz_session.lib_of_MBAP_protocol))
        lgr.info('Value  of test MBAP Unit id: %r' %(fuzz_session.lib_of_MBAP_Unit_id))
        lgr.info('total of test  MBAP Unit id: %d' %len(fuzz_session.lib_of_MBAP_Unit_id))
        lgr.info('Value of test MBAP  length: %r' %fuzz_session.lib_of_MBAP_length)
        lgr.info('total of test  MBAP length: %d' %len(fuzz_session.lib_of_MBAP_length))
 

    def config_test_fields (self) :

        """
        log set configuration quantity_of_x_list, address for single (1-way)  and pairs  (2-way) in PDU fields
        """
        
        lof=list_of_fuzz() 
        lgr.info('')
        lgr.info('      > Set configuration quantity_of_x, address for single (1-way) and pairwise (2-way) PDU tests')
        lgr.info('')
        lgr.info('address COILS for single test : %s' %fuzz_session.fuzz_addre_COILS)
        lgr.info('total of test num address COILS for single test : %d' %len(fuzz_session.fuzz_addre_COILS))
        lgr.info('address COILS for pairwise test: %s' %fuzz_session.fuzz_addre_COILS_cart)
        lgr.info('num COILS for pairwise test: %d' %len(fuzz_session.fuzz_addre_COILS_cart)) 
        lgr.info('')
        lgr.info('address HO_REG for single test: %s' % fuzz_session.fuzz_addre_HO_REG)
        lgr.info('total of test num HO REG  for single test: %d' %len(fuzz_session.fuzz_addre_HO_REG))
        lgr.info('address HO_REG for pairwise test: %s' %fuzz_session.fuzz_addre_HO_REG_cart)
        lgr.info('num HO REG  for pairwise test: %d' %len(fuzz_session.fuzz_addre_HO_REG_cart))
        lgr.info('')
        lgr.info('address DISCRETE INPUTS for single test: %s' % fuzz_session.fuzz_addre_DIS_IN)
        lgr.info('')
        lgr.info('total of test DISCRETE INPUTS for single test: %d' %len(fuzz_session.fuzz_addre_DIS_IN))
        lgr.info('address DISCRETE INPUTS for pairwise test: %s' %fuzz_session.fuzz_addre_DIS_IN_cart)
        lgr.info('num  DISCRETE_INPUTS for pairwise test: %d' %len(fuzz_session.fuzz_addre_DIS_IN_cart))
        lgr.info('')
        lgr.info('address READ_INPUT_REGISTERS for single test: %s' % fuzz_session.fuzz_addre_IN_REG)
        lgr.info('total of test  READ INPUT REGISTERS for single test: %d' %len(fuzz_session.fuzz_addre_IN_REG))
        lgr.info('address READ_INPUT_REGISTERS for pairwise test: %s' %fuzz_session.fuzz_addre_IN_REG_cart)
        lgr.info('num  READ INPUT REGISTERS for pairwise test: %d' %len(fuzz_session.fuzz_addre_IN_REG_cart))
        lgr.info('')                   
        lgr.info('quantity_of_x  coils for single test: %s' %fuzz_session.quantity_of_x_list_coil)
        lgr.info('total of test quantity_of_x coils for single test: %d' %len(fuzz_session.quantity_of_x_list_coil))
        lgr.info('')
        lgr.info('quantity_of_x  coils for pairwise test: %s' %fuzz_session.quantity_of_x_list_coil_cart)
        lgr.info('num quantity_of_x coils  for pairwise test: %d' %len(fuzz_session.quantity_of_x_list_coil_cart))
        lgr.info('')
        lgr.info('quantity_of_x register for single test: %s' %fuzz_session.quantity_of_x_list_reg)
        lgr.info('')
        lgr.info('total of test quantity_of_x register for single test: %d' %len(fuzz_session.quantity_of_x_list_reg))
        lgr.info('quantity_of_x register for pairwise test: %s' %fuzz_session.quantity_of_x_list_reg_cart)
        lgr.info('num quantity_of_x register for pairwise test: %d' %len(fuzz_session.quantity_of_x_list_reg_cart))
        lgr.info('VALUE TEST for pairwise test: %r' %lof.lib_word_cart())
        lgr.info('num value test for pairwise test: %d' %len(lof.lib_word_cart()))
        lgr.info('')
        
        #use FC05 FC06 FC22,FC 08 (0x08) Diagnostics--data 
        lgr.info('     > library for single (1-way) test \n')
        lgr.info('test  library  (word16/32): %r'%fuzz_session.values_test)
        lgr.info('test  library  (word16/32): %d' %len(fuzz_session.values_test))

        lgr.info('test library for_output_value_(FC15,FC16): %r'%fuzz_session.output_value_test)
        lgr.info('test library for_output_value_(FC15,FC16): %d' %len(fuzz_session.output_value_test))

        lgr.info('library for test byte count field: %r'%fuzz_session.byte_count_test)
        lgr.info('num library for test byte count field:%d' %len(fuzz_session.byte_count_test))

        lgr.info('library for test Sub-function codes: %r'%fuzz_session.lib_test_sub_diag)
        lgr.info('num library for test Sub-function codes: %d' %len(fuzz_session.lib_test_sub_diag))

    def config_test_format(self):
        """
        log  configuration for fuzzing not specification message len and Dumplicate
        class interesting byte and and random/smart characters
        PAIRWISE test in ADU Dumplicate -create for FC01-FC04.. dir="tmp/" and  save  .csv file for test

        """  
        tip=test_illegal_PDU();pairsfind=pairs_address_qua()       
        #only log config not set in np table  
        lgr.info('')
        lgr.info("     > Initializes from CSV, address vs quantity for test format (dumplicate ADU/PDU)")
        pairsfind.pair_format_dumpl(READ_COILS,tip.A_CO,tip.QC,fuzz_session.MAX_COILS,fuzz_session.MIN_COILS )
        pairsfind.pair_format_dumpl(READ_DISCRETE_INPUTS,tip.A_DI,tip.QC,fuzz_session.MAX_DIS_IN,fuzz_session.MIN_DIS_IN)
        pairsfind.pair_format_dumpl(READ_HOLDING_REGISTERS,tip.A_HR,tip.QH,fuzz_session.MAX_HO_REG,fuzz_session.MIN_HO_REG)
        pairsfind.pair_format_dumpl(READ_INPUT_REGISTERS,tip.A_IR,tip.QH,fuzz_session.MAX_IN_REG,fuzz_session.MIN_IN_REG)    

        lgr.info('')
        lgr.info('     > Set configuration for fuzzing not specification message len and Dumplicate (ADU address x quantity_of)')
        lgr.info('')
        lgr.info('address COILS: %s' %tip.A_CO)
        lgr.info('num address COILS: %d' %len(tip.A_CO))            
        lgr.info('')
        lgr.info('address HO_REG: %s' % tip.A_HR)
        lgr.info('num address HO REG: %d' %len(tip.A_HR))
        lgr.info('')
        lgr.info('address DISCRETE_INPUTS: %s' % tip.A_DI)
        lgr.info('')
        lgr.info('num DISCRETE INPUTS: %d' %len(tip.A_DI))
        lgr.info('')
        lgr.info('address READ_INPUT_REGISTERS: %s' % tip.A_IR)
        lgr.info('num READ_INPUT REGISTERS: %d' %len(tip.A_IR))
        lgr.info('')
        lgr.info('quantity_of_x_ for coils: %s' %tip.QC)
        lgr.info('')
        lgr.info('num quantity_of_x_ for coils: %d' %len(tip.QC))
        lgr.info('')
        lgr.info('quantity_of_x_ for register: %s' %tip.QH)
        lgr.info('')
        lgr.info('num quantity_of_x_ for register: %d' %len(tip.QH))
        lgr.info('')
        lgr.info('value of len for dumplicate ADU test: %s' %tip.list_of_dumpl_number())
        lgr.info('')
        #Prepare to fuzz test format_message     
        lgr.info('num quantity list dumplicate ADU: %d' %len(tip.list_of_dumpl_number()))      
        lgr.info('test of lengths with random or interesting characters: %s' % fuzz_session.illegal_pdu_len)
        lgr.info('')
        lgr.info('Set class  of interesting message or buffer bytes: %s ' % fuzz_session.test_class_of_msg)
        lgr.info('number test case per FC of length illegal message PDU: %d' %len(fuzz_session.illegal_pdu_len))
        lgr.info('---------------------------------------------------------------------------------------------------------\n')
        
