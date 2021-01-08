#!/usr/bin/env python
# -*- coding: utf-8 -*-

""" Share global variables across modules """
fuzz_mode =False
search_mode=False

"""for read pcap file"""
pcap_mode=False

"""define for search mapping block/for black-box"""
s_address=0
l_address=65535
step=1024

"""define for memory dump attack"""
quantity=100  

"""list calculate fuzz  for FC """
fuzz_addre_COILS=[]                                          
fuzz_addre_DIS_IN=[]
fuzz_addre_IN_REG=[]
fuzz_addre_HO_REG=[]
quantity_of_x_list_coil=[]
output_value_test=[]
quantity_of_x_list_reg=[]
values_test=[]
byte_count_test=[]
lib_test_sub_diag=[]
output_value_test=[]

""" test one way for MBAP field"""
lib_of_MBAP_transid=[];lib_of_MBAP_protocol=[]
lib_of_MBAP_Unit_id=[];lib_of_MBAP_length=[]

""" test  for FC files, FC 20, 21"""
count_byte_test=[]
ref_byte_test=[]
fuzz_files_rum=[]
fuzz_files_rec=[]
record_length=[]

"""for all list min/max address"""
            
MIN_COILS =0
MAX_COILS =0
MIN_IN_REG=0
MAX_IN_REG=0
MIN_DIS_IN=0
MAX_DIS_IN=0
MIN_HO_REG=0
MAX_HO_REG=0

"""define for num_of_reguest and normal and item list index for interesting byte"""
num_of_request=0;normal_request=1000
item_list=0;item_list_hex=0

"""define for statistics check PDU after legal PDU inserts a heuristic illegal length"""
PDU_valid=0;PDU_invalid=0

"""define for statistics 1-way check PDU field"""
address_invalid=0
address_valid=0
address_quantity_valid=0
address_quantity_invalid=0
quantity_valid=0
quantity_invalid=0
value_invalid=0
value_valid=0 
byte_count_valid=0
byte_count_invalid=0

""" define  FC 23  for statistics 1-way check PDU field"""
read_starting_address_valid=0
read_starting_address_invalid=0
quantity_to_Read_invalid=0
quantity_to_Read_valid=0
read_address_quantity_invalid=0
read_address_quantity_valid=0
write_starting_address_invalid=0
write_starting_address_valid=0
quantity_to_Write_invalid=0
quantity_to_Write_valid=0
write_address_quantity_invalid=0
write_address_quantity_valid=0
write_byte_count_invalid=0
write_byte_count_valid=0

"""for diagnostics"""
subfunction_valid=0
subfunction_invalid=0
data=0

"""22 (0x16) Mask Write Register"""
test_or_mask=0;test_and_mask=0


""" 43 Read Device Information """
mei_type_valid=0
mei_type_invalid=0 
read_code_valid=0
read_code_invalid=0
object_id_valid=0
object_id_invalid=0 

"""use test field PDU and MBAP"""
starting_address=0
quantity_of_x=0
output_value=0
read_starting_address=0
write_starting_address=0
#f_record1='FileRecord(file=%d, record=%d, length=%d)' % (0,0,0)
Pointer_address=0
quantity_to_Read=0
quantity_to_Write=0

"""use test field PDU FC 43"""
mei_type=0;read_code=0;object_id=0

"""use test field PDU FC 20,21"""
Reference_Type=0
field1_valid=0
field1_invalid=0
field2_valid=0
field2_invalid=0
field3_valid=0
field3_invalid=0
field4_valid=0
field4_invalid=0
field5_invalid=0
field5_valid=0
field6_valid=0
field6_invalid=0

protocol_id=0
length=253
unit_id=-1
z=1

"""fuzz_random =='string_char' """
attackstring=""
attacksize=0

"""flag len of list and list of test attach string"""
len_of_list=1
illegal_pdu_len =[]
bytehex=[]
flag_init_illegal_pdu_len=True

"""def priority fot test suite"""
priority=0

""" def FC for test_dumplicate_ADU"""
FC_dumplicate_ADU=[1,2,3,4,5,6,15,16]
dumplicate_number=[]
byte_remove=0

""" def FC for test_fuzz_field"""

test_field_of_data=[]

test_flag_fc=True
test_flag_parameter_PDU=True
flag_reguest=True

public_codes=[]
user_codes=[]
exeption_codes=[]

flag_public_codes=True
flag_user_codes=True
flag_exeption_codes=True

case_FC16=True
case_FC15=True
case_FC23=True

flag_test_FC08_pair=False

"""temp list for fuzz testing in PDU fields"""
tmp_test_list=[]
fields_of_list=[]
tmp_list_of_case=[]

rows_of_cover=[]

"""flag for log,boundaries check address+quantity or ou to f spec len"""
flag_boundaries=0
flag_len_out_of_spec=0
mbap_error=0
length_not_f=0
# row_number and  non_f_num_of_request   case test fuzz and not fuzz testing 
FCmergedlist=[]
row_number=0
non_f_num_of_request=0

"""add for except socket.timeout in class SetupAndTeardown(object) """
socket_flag=False
stimeout=0
num=0
num_recon=0
receive_flag=False
receive_timeout=0

"""This  list operation fuzz testing'''
test of single fields, Combinatorial 2-way field MBAP and PDU 
e.g    test_field_MBAP=[ 'protoId', 'len','unitId','Combinatorial']
test for not spec len message Modbus PDU, fp= ['test_dumplicate_ADU','remove']
"""
test_field_MBAP=[]
test_field_read_fc=[] 
test_field_write_fc=[]
test_field_mult_fc=[]
test_FC_23=[]
test_wr_mask_param=[]
test_FC43=[]
Diagnostics_FC_param=[]
test_field_Read_File_record=[]
test_field_Write_File_record=[]
fp= []
attack_byte_PDU=[]



