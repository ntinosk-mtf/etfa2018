#!/usr/bin/env python
# -*- coding: utf-8 -*-
#------------------------------------------------------------------------------------
#This class about  dictionary of  list operation fuzz testing, dict_operation_f_test.py
#-----------------------------------------------------------------------------------
import fuzz_session

class dict_fuzz_object(object):
    
    def __init__(self):
               

        self.Dict_fuzz_operation = {

            'test_field_MBAP':['transId', 'protoId', 'len','unitId','Combinatorial'],
            'test_field_read_fc':['address', 'quantity_of_x', '2-way'] ,
            'test_field_write_fc':['address', 'output_value', '2-way'],
            'test_field_mult_fc':['address', 'quantity_of_x','byte_count','output_value','2-way'],
            'test_FC_23':['1-way_read_starting_address', '1-way_quantity_to_Read','1-way_write_starting_address','1-way_quantity_to_Write','1-way_write_byte_count','2-way'],
            'test_wr_mask_param':['address','or_mask','and_mask'],
            'test_FC43':['1-way_mei_type','1-way_read_code','1-way_object_id','2-way' ],
            'Diagnostics_FC_param':['1-way_sub-function','1-way_data','2-way'],
            'test_field_Read_File_record':['Byte_Count','Reference_Type','File_number','Record_number','Record_length','2-way'],
            'test_field_Write_File_record':['Data length','Reference Type','File number','Record number','Record length','Record data','2-way'] ,          
            'fp': ['test_dumplicate_ADU','test_illegal_len_PDU','remove'],
            'attack_byte_PDU':['attack_randByte','attack_inter_byte'],                  
           
        }  

    #return dictionary
    def dict_operation(self): return self.Dict_fuzz_operation        
        
    #return key value
    def dict_operation_key(self,key):        
        return self.Dict_fuzz_operation.get(key)

    def int_fuzz_operation(self):                
            fuzz_session.test_field_MBAP= self.dict_operation_key('test_field_MBAP') 
            fuzz_session.test_field_read_fc= self.dict_operation_key('test_field_read_fc')
            fuzz_session.test_field_write_fc=self.dict_operation_key('test_field_write_fc')  
            fuzz_session.test_field_mult_fc=self.dict_operation_key('test_field_mult_fc')
            fuzz_session.test_FC_23=self.dict_operation_key('test_FC_23')
            fuzz_session.test_wr_mask_param=self.dict_operation_key('test_wr_mask_param')
            fuzz_session.test_FC43=self.dict_operation_key('test_FC43')
            fuzz_session.Diagnostics_FC_param=self.dict_operation_key('Diagnostics_FC_param')
            fuzz_session.test_field_Read_File_record=self.dict_operation_key('test_field_Read_File_record')
            fuzz_session.test_field_Write_File_record=self.dict_operation_key('test_field_Write_File_record')
            fuzz_session.fp=self.dict_operation_key("fp") 
            fuzz_session.attack_byte_PDU=self.dict_operation_key('attack_byte_PDU')
