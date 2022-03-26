#!/usr/bin/env python
# -*- coding: utf-8 -*-


import traceback
import fuzz_session
import modbus_tk.utils
import struct 
import logging.handlers as handlers
from defines import * 
from utils_b import *

logger = modbus_tk.utils.create_logger("console")# create logger-
lgr=logging.getLogger('')

#------------------------------------------------------------------------------------
# Fuzzig none, random valid  message send
#------------------------------------------------------------------------------------
class fuzzer_None(object):
    """ 
    Fuzzing none, case fuzz_session.priority=4
    None Fuzzing, def num_of_request=1000 for FC
    """
        
    def __init__(self):
        pass
                    
    def fuzz_field_None(self,pdu):
        adu=""
        if fuzz_session.non_f_num_of_request ==fuzz_session.normal_request-1:
            fuzz_session.flag_reguest=False;fuzz_session.non_f_num_of_request=-1
        self.case_of_fields(pdu)
        return adu,pdu   
    
    def case_of_fields(self,pdu):
       
        self.function_code=int.from_bytes(pdu[0:1], byteorder='big')     
        lgr.info('The function_code is % s'  % self.function_code)
        fuzz_session.non_f_num_of_request  += 1
        
        while True:
            
            try:

                if self.function_code == READ_COILS :
                    lgr.info('FC 01: READ_COILS ')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info('starting_address: %d,quantity_of_x: %d' % (starting_address, quantity_of_x))              
                    break

                elif self.function_code == READ_DISCRETE_INPUTS :    
                    lgr.info('FC 02: READ_DISCRETE_INPUTS')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info(' starting_address: %d,quantity_of_x:%d' % (starting_address, quantity_of_x))                
                    break
                
                elif self.function_code == READ_HOLDING_REGISTERS :    
                    lgr.info('FC 03: READ_HOLDING_REGISTERS')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info(': %d,%d' % (starting_address, quantity_of_x))
                    break

                elif self.function_code == READ_INPUT_REGISTERS :    
                    lgr.info('FC 04: READ_INPUT_REGISTERS')
                    starting_address, quantity_of_x = struct.unpack(">HH", pdu[1:5])
                    lgr.info(': %d,%d' % (starting_address, quantity_of_x))
                    break    

                elif self.function_code == WRITE_SINGLE_COIL :    
                    lgr.info('FC 05: WRITE SINGLE COIL')
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    lgr.info('starting_address: %d,output_value: %d' % (starting_address,output_value ))
                    break    
                
                elif self.function_code == WRITE_SINGLE_REGISTER :    
                    lgr.info('FC 06: WRITE_SINGLE_REGISTER')
                    starting_address,output_value = struct.unpack(">HH", pdu[1:5])
                    lgr.info('starting_address: %d,output_value: %d' % (starting_address,output_value ))
                    break 

                elif self.function_code == WRITE_MULTIPLE_COILS :    
                    lgr.info('FC 15: WRITE_MULTIPLE_COILS')
                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    lgr.info('starting_address: %d,quantity_of_x: %d,byte_count: %d' % (starting_address, quantity_of_x, byte_count ))
                    break     

                elif self.function_code == WRITE_MULTIPLE_REGISTERS :    
                    lgr.info('FC 16: WRITE_MULTIPLE_REGISTERS')
                    starting_address, quantity_of_x, byte_count = struct.unpack(">HHB", pdu[1:6])
                    lgr.info('starting_address: %d,quantity_of_x: %d,byte_count: %d' % (starting_address, quantity_of_x, byte_count ))
                    break     
                
                elif self.function_code == Mask_Write_Register :    
                    lgr.info('FC 22: Mask Write Register')
                    starting_address, and_mask, or_mask = struct.unpack(">HHH", pdu[1:7])
                    lgr.info('starting_address:%d,and_mask: %d,or_mask%d' % (starting_address, and_mask, or_mask))
                    break 

                elif self.function_code == Read_Write_Multiple_Registers :    
                    lgr.info('FC 23: Read_Write_Multiple_Registers')
                    read_starting_address, quantity_to_Read, write_starting_address, quantity_to_Write,write_byte_count = struct.unpack(">HHHHB", pdu[1:10])
                    lgr.info('read_starting_address: %d,quantity_to_Read: %d,write_address: %d,quantity_to_Write: %d,write_byte_count: %d' % (read_starting_address, quantity_to_Read, \
                    write_starting_address, quantity_to_Write,write_byte_count))
                    break 


                elif self.function_code == Read_File_record:
                    lgr.info('FC 20: Read_File_record')
                    Byte_Count,Reference_Type,File_number,File_record,Record_length=struct.unpack(">BBHHH", pdu[1:9])
                    lgr.info('Byte_Count: %d,Reference_Type: %d,File_number: %d,File_record: %d,Record_length: %d' % (Byte_Count,Reference_Type,File_number,\
                    File_record,Record_length))
                    break

                elif self.function_code == Write_File_record:    
                    lgr.info('FC 21: Write_File_record ')
                    Data_length,Reference_Type,File_number,Write_record,Record_length= struct.unpack(">BBHHH", pdu[1:9])
                    lgr.info('Data_length: %d,Reference_Type: %d,File_number: %d,Write_record: %d,Record_length: %d' % (Data_length,Reference_Type,File_number,Write_record,Record_length))
                    break

                elif self.function_code == Read_FIFO_queue  :    
                    lgr.info('FC 24 : Read_FIFO_queue')
                    Pointer_address, = struct.unpack(">H", pdu[1:3])
                    lgr.info(': %d' % (Pointer_address))
                    break 
                
                elif self.function_code == Read_device_Identification  :    
                    lgr.info('FC 43 : Read_device_Identification')
                    mei_type,read_code,object_id = struct.unpack(">BBB", pdu[1:5])
                    lgr.info('mei_type: %d,read_code: %d,object_id: %d' % (mei_type,read_code,object_id))
                    break

                elif self.function_code == Diagnostics :    
                    lgr.info('FC 8 : Diagnostics ')               
                    fuzz_session.flag_test_FC08_pair=False
                    break 

                elif self.function_code == Read_Exception_Status :    
                    lgr.info('FC 7 : Read_Exception_Status/not parameters PDU ')
                    fuzz_session.flag_reguest=False                    
                    break

                elif self.function_code == Get_Comm_Event_Counter :    
                    lgr.info('FC 11 : Get_Comm_Event_Counter/not parameters PDU ')
                    fuzz_session.flag_reguest=False
                    break             
                
                elif self.function_code == Get_Comm_Event_Logs  :    
                    lgr.info('FC 12 : Get_Comm_Event_Logs / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break   
                
                elif self.function_code == Report_Slave_Id  :    
                    lgr.info('FC 17 : Report_Slave_Id / not parameters PDU ')
                    fuzz_session.flag_reguest=False 
                    break        
                else: 
                    lgr.info('Other function_code: %d ....' % self.function_code)
                    break  
            
            #default for detect error as er
            except  Exception as er:                                                                  
               lgr.error(er);lgr.error('Exit and try creating socket again')                                           
               time.sleep(1.0)
               pass # in process normal no  # traceback.print_exc()    
               #break  # in process   with traceback.print_exc()   
            return  pdu           
