
#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2018
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""
import numpy as np

test_suites_list = [('test_MBAP', 1.0), ('test_message_PDU', 2.0), ('test_field_PDU', 3.0),('Not_fuzz',4.0)]
host=None       
log_dir = "./log/"
log_file=""
slave=1

#list of supported address   
supported_address_coil = []
supported_address_input_reg = []
supported_address_dist_input = []
supported_address_hold_reg = []

#list of not response address 
not_response_address_coil = []
not_response_address_input_reg = []
not_response_address_dist_input = []
not_response_address_hold_reg = []

#supported modbus_tk functions (8)
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_COILS = 15
WRITE_MULTIPLE_REGISTERS = 16 

# add extra function for fuzzer -insert from pymodbus 2.x.x.(module:file_message.py)
# Encapsulated Interface Transport=43       (0x2B) MEI_sub_function_code  13/14
Read_device_Identification=43
Read_Write_Multiple_Registers=23          #(0x17)   
Mask_Write_Register=22                    #(0x16)
Read_FIFO_queue=24                        #(0x18)
Read_File_record=20                       #(0x14) 
Write_File_record=21                      #(0x15)  
Read_Exception_Status=7
Diagnostics=8
Get_Comm_Event_Counter=11
Get_Comm_Event_Logs=12
Report_Slave_Id=17

# modbus exception codes support modbus_tk
ILLEGAL_FUNCTION = 1
ILLEGAL_DATA_ADDRESS = 2
ILLEGAL_DATA_VALUE = 3
SLAVE_DEVICE_FAILURE = 4
SLAVE_DEVICE_BUSY = 6
MEMORY_PARITY_ERROR = 8
ACKNOWLEDGE = 5
NEGATIVE_ACKNOWLEDGE = 7
GATEWAY_PATH_UNAVAILABLE = 10
GATEWAY_TARGET_DEVICE_FAILED_TO_RESPOND = 11


#Time setting for duration, #init total number of request
start_time=0;end_time=0;num_of_request=0

#Define value for MIN MAX address of bank 
MIN_COILS=0
MAX_COILS=0
MIN_IN_REG=0
MAX_IN_REG=0
MIN_DIS_IN=0
MAX_DIS_IN=0
MIN_HO_REG=0
MAX_HO_REG=0

#Define for function 20,21,22, 
#Each file contains 10000 records, addressed 0000 to 9999
start_address_reco=0
last_address_reco=9999                           
offset_fuzzer_reco=128 
mem_step_reco=64 

#pairs of COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
#integer_boundaries for byte count REG: quantity_of_x_list) use  in test_dumplicate_ADU and test fiels PDU 
#directly initialize , numpy table,x= np.array([], dtype=np.init)

pairwice_MBAP=np.array([], dtype=np.int16)
pairwice_READ_COILS=np.array([], dtype=np.int16)
pairwice_READ_DISCRETE_INPUTS=np.array([], dtype=np.int16)
pairwice_READ_HOLDING_REGISTERS=np.array([], dtype=np.int16)
pairwice_READ_INPUT_REGISTERS=np.array([], dtype=np.int16)
pairwice_WRITE_SINGLE_COIL= np.array([], dtype=np.int16)
pairwice_WRITE_SINGLE_REGISTER= np.array([], dtype=np.int16)
pairwice_byte_count_value=[]

pairwice_Read_device_Ident=[] 
pairwice_file=[]  
lib_word=[]
pairwice_Quant_vs_byte_count=np.array([], dtype=np.int16)
lib_byte_count=[]

#bount value interesting value in word 8 or 16 bit
MAX_OF_WORD16=65535
MAX_OF_WORD8=255
MIN_OF_WORD=0

#max is bountery of QUANT FC1, FC02, FC03, FC04
MAX_QUANT_COIL_FC01=1968
MAX_QUANT_COIL_FC15=2000
MAX_QUANT_REG_FC23=121
MAX_QUANT_REG_FC16=125

#FC 20, 21, bount value interesting value
MAX_REF_TYPE_File_record=6
MIN_B_COUNT_File_record=7
MAX_B_COUNT_File_record=245
MAX_RECORD_NUM_File_record=9999
MAX_FILE_NUM_File_record=10
MAX_REC_LEN_File_record=122
