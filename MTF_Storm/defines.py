
#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2015/2018
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""
import numpy as np

request = (
               
                (0x01, '\x01\x00\x01\x00\x01'),                       # read coils
                (0x02, '\x02\x00\x01\x00\x01'),                       # read discrete inputs
                (0x03, '\x03\x00\x01\x00\x01'),                       # read holding registers
                (0x04, '\x04\x00\x01\x00\x01'),                       # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07'),                                       # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b'),                                       # get comm event counters
                (0x0c, '\x0c'),                                       # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08\x01\x00\xff'),           # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02\x04\0xff\xff'),          # write multiple registers
                (0x11, '\x11'),                                       # report slave id
                (0x14, '\x14\x0e\x06\x00\x04\x00\x01\x00\x02' \
                       '\x06\x00\x03\x00\x09\x00\x02'),               # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' \
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x00\x01\x00\x01\x00\x01\x00\x01\x02\x12\x34'),# read/write multiple registers
                (0x18, '\x18\x00\x01'),                               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x00'),                           # read device identification                       
        )
response = (
                (0x01, '\x01\x01\x01'),                               # read coils
                (0x02, '\x02\x01\x01'),                               # read discrete inputs
                (0x03, '\x03\x02\x01\x01'),                           # read holding registers
                (0x04, '\x04\x02\x01\x01'),                           # read input registers
                (0x05, '\x05\x00\x01\x00\x01'),                       # write single coil
                (0x06, '\x06\x00\x01\x00\x01'),                       # write single register
                (0x07, '\x07\x00'),                                   # read exception status
                (0x08, '\x08\x00\x00\x00\x00'),                       # read diagnostic
                (0x0b, '\x0b\x00\x00\x00\x00'),                       # get comm event counters
                (0x0c, '\x0c\x08\x00\x00\x01\x08\x01\x21\x20\x00'),   # get comm event log
                (0x0f, '\x0f\x00\x01\x00\x08'),                       # write multiple coils
                (0x10, '\x10\x00\x01\x00\x02'),                       # write multiple registers
                (0x11, '\x11\x03\x05\x01\x54'),                       # report slave id (device specific)
                (0x14, '\x14\x0c\x05\x06\x0d\xfe\x00\x20\x05' 
                       '\x06\x33\xcd\x00\x40'),                       # read file record
                (0x15, '\x15\x0d\x06\x00\x04\x00\x07\x00\x03' 
                       '\x06\xaf\x04\xbe\x10\x0d'),                   # write file record
                (0x16, '\x16\x00\x01\x00\xff\xff\x00'),               # mask write register
                (0x17, '\x17\x02\x12\x34'),                           # read/write multiple registers
                (0x18, '\x18\x00\x01\x00\x01\x00\x00'),               # read fifo queue
                (0x2b, '\x2b\x0e\x01\x01\x00\x00\x01\x00\x01\x77'),   # read device identification
        )

bad = (                                                        #ITEM 12  
        (0x80, '\x80\x00\x00\x00'),                            # Unknown Function
        (0x81, '\x81\x00\x00\x00'),                            # error message
        (0x90, '\x90\x00\x00\x00'),
        (0x91, '\x91\x00\x00\x00'),
        (0x92, '\x92\x00\x00\x00'),
        (0x93, '\x93\x00\x00\x00'),
        (0x94, '\x94\x00\x00\x00'),
        (0x95, '\x95\x00\x00\x00'),
        (0x96, '\x96\x00\x00\x00'),
        (0x97, '\x97\x00\x00\x00'),
        (0x98, '\x98\x00\x00\x00'),
        (0x99, '\x99\x00\x00\x00'),                           
      )

exception = (
        (0x81, '\x81\x01\xd0\x50'),                           # illegal function exception
        (0x82, '\x82\x02\x90\xa1'),                           # illegal data address exception
        (0x83, '\x83\x03\x50\xf1'),                           # illegal data value exception
        (0x84, '\x84\x04\x13\x03'),                           # skave device failure exception  -crach
        (0x85, '\x85\x05\xd3\x53'),                           # acknowledge exception
        (0x86, '\x86\x06\x93\xa2'),                           # slave device busy exception
        (0x87, '\x87\x08\x53\xf2'),                           # memory parity exception
        (0x88, '\x88\x0a\x16\x06'),  
        (0x89, '\x89\x0b\xd6\x56'),                           # gateway target failed exception
        
       
      )


diagnostics = (
        
        (00, '\x08\x00\x00\x00\x00'),
        (01, '\x08\x00\x01\x00\x00'),                               #restartCommunaications
        (02, '\x08\x00\x02\x00\x00'),                               #ReturnDiagnosticRegisterResponse
        (03, '\x08\x00\x03\x00\x00'),                               #ChangeAsciiInputDelimiterResponse
        (04, '\x08\x00\x04'),                                       #ForceListenOnlyModeResponse
        (05, '\x08\x00\x00\x00\x00'),                               #ReturnQueryDataResponse
        (06, '\x08\x00\x0a\x00\x00'),                               #ClearCountersResponse
        (07, '\x08\x00\x0b\x00\x00'),                               #ReturnBusMessageCountResponse
        (10, '\x08\x00\x0c\x00\x00'),                               #ReturnBusCommunicationErrorCountResponse
        (11, '\x08\x00\x0d\x00\x00'),                               #ReturnBusExceptionErrorCountResponse
        (12, '\x08\x00\x0e\x00\x00'),                               #ReturnSlaveMessageCountResponse
        (13, '\x08\x00\x0f\x00\x00'),                               #ReturnSlaveNoReponseCountResponse
        (14, '\x08\x00\x10\x00\x00'),                               #ReturnSlaveNAKCountResponse
        (15, '\x08\x00\x11\x00\x00'),                               #ReturnSlaveBusyCountResponse
        (16, '\x08\x00\x12\x00\x00'),                               #ReturnSlaveBusCharacterOverrunCountResponse
        (17, '\x08\x00\x13\x00\x00'),                               #ReturnIopOverrunCountResponse
        (18, '\x08\x00\x14\x00\x00'),                               #ClearOverrunCountResponse
        (19, '\x08\x00\x15' + '\x00\x00' * 55),                     #etClearModbusPlusResponse
        (20, '\x08\x00\x01\x00\xff')                                #restartCommunaications
      )

little_endian_payload = (
                       (1, '\x01\x02\x00\x03\x00\x00\x00\x04\x00\x00\x00\x00'), 
                       (2, '\x00\x00\x00\xff\xfe\xff\xfd\xff\xff\xff\xfc\xff'),
                       (3, '\xff\xff\xff\xff\xff\xff\x00\x00\xa0\x3f\x00\x00'),
                       (4, '\x00\x00\x00\x00\x19\x40\x74\x65\x73\x74\x11'),
                       )

#-----------------------------------------------------------------------------------------------------------
test_suites_list = [('test_MBAP', 1.0), ('test_message_PDU', 2.0), ('test_field_PDU', 3.0),('Not_fuzz',4.0)]
#-----------------------------------------------------------------------------------------------------------
host=None          
log_dir = "./log/"
csvFile= "" 
log_file="" 
pcap_file="" 
filtered_pcap="filtered.pcap"
mod_file_response='filter_resp.pcap'
mod_file_request='filter_reg.pcap'   

#supported modbus_tk functions (8)
READ_COILS = 1
READ_DISCRETE_INPUTS = 2
READ_HOLDING_REGISTERS = 3
READ_INPUT_REGISTERS = 4
WRITE_SINGLE_COIL = 5
WRITE_SINGLE_REGISTER = 6
WRITE_MULTIPLE_COILS = 15
WRITE_MULTIPLE_REGISTERS = 16 

# add extra function for fuzzer -insert from pymodbus 1.2.0 (module:file_message.py)
# Encapsulated Interface Transport=43       (0x2B) MEI_sub_function_code  13/14
Read_device_Identification=43
Read_Write_Multiple_Registers=23           #(0x17)   
Mask_Write_Register=22                     #(0x16)
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

# define for search mapping block/for black-box
s_address=0
l_address=65535
offset_address=65535                       # step from star
step=32768                                 # step for search memory map
quan_step= 1                               # fix step for search map /def chk_list
num_of_search=0
   
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

#define for function add block/fuzzing 
slave=1
start_address=0
last_address=40000
size_of_bank=9999
offset_fuzzer=0                             # up - down bank memory 
name_of_block=None
value_range=64                              # quantity_of_x how value read 
mem_step=1024                               # how match move to memory -step
FCmergedlist=[]                             # list fc for merge csv config file

#set step for read block memory with memory dump attack-ok
scv_table='dump_memory.csv'
quantity=100
step_mem_dump=100

#Time setting for duration, #init total number of request
start_time=0
end_time=0
num_of_request=0

#Define value for MIN MAX Address of bank 
MIN_COILS=0
MAX_COILS=0
MIN_IN_REG=0
MAX_IN_REG=0
MIN_DIS_IN=0
MAX_DIS_IN=0
MIN_HO_REG=0
MAX_HO_REG=0

#define for function 20,21,22, 
#Each file contains 10000 records, addressed 0000 to 9999
start_address_reco=0
last_address_reco=9999                           
offset_fuzzer_reco=128 
mem_step_reco=64 

"""cross product pairs of COILS,DIS_IN,IN_REG,HO_REG and integer_boundaries for byte count coil: quantity_of_x_list
integer_boundaries for byte count REG: quantity_of_x_list) use  in test_dumplicate_ADU and test fiels PDU 
directly initialize , numpy table 
x= np.array([], dtype=np.init)

"""
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


