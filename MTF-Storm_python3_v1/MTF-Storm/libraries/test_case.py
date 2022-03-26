#!/usr/bin/env python
# -*- coding: utf-8 -*-
#library for write results to file *.csv for test single field,write results  Coverage  "{:.1%}".format(0.1234)-> '12.3%'

import sys
import os
import csv
import fuzz_session
from defines import *
import modbus_tk.utils 
from utils_b import *
import logging.handlers as handlers
from datetime import datetime

logger = modbus_tk.utils.create_logger("console") # create logger- 
lgr=logging.getLogger('')

class test_case_coverage:

    def __init__(self ):        
        """ Constructor. Set the Initializing settings

        """ 
    
    def reset(self):
        #reset counters
        fuzz_session.field1_valid=0
        fuzz_session.field1_invalid=0
        fuzz_session.field2_valid=0
        fuzz_session.field2_invalid=0
        fuzz_session.field3_valid=0
        fuzz_session.field3_invalid=0
        fuzz_session.field4_valid=0
        fuzz_session.field4_invalid=0
        fuzz_session.field5_valid=0
        fuzz_session.field5_invalid=0
        fuzz_session.field6_valid=0
        fuzz_session.field6_invalid=0
        fuzz_session.address_quantity_invalid=0
        fuzz_session.address_quantity_valid=0
    
    def test_case (self,function_code,test_field,test_fields,tmp_test_list,dir="test_tuple"):
        """
        this method write results to file *.csv for test single field '
        tmp_test_list is np array

        """
             
        csvfile=dir+'/test_FC%s_%s.csv' % (function_code,test_field)
        csvfile_bak=dir+'/test_FC%s_%s.bak' % (function_code,test_field)
                
        if not os.path.exists(log_dir+dir):
        	 os.makedirs(log_dir+dir)
        elif os.path.exists(log_dir+csvfile):
            lgr.warn("    > file name exist ..rename")
            os.rename(log_dir+csvfile, log_dir+csvfile_bak)
        else:
            lgr.info("    > Write test case tuples..")
            
        try :
	        with open(log_dir+csvfile,"w") as f:                
	            csvwriter = csv.writer(f)
	            f.write('\nMTF-Storm v1.0 python3 fuzzing run\n')
	            #f.write('#---------------------------#\n')
	            f.write('\nDate of run:%s\n'%datetime.now())
	            f.write('Fuzzing field :%s \n'%(test_field))
	            f.write('\nFC: %d (0x%02X)..,software under test: %s \n'%(function_code,function_code,log_dir))
	            f.write("Total no. of rows: %d \n"%(len(tmp_test_list)) )
	            f.write('Field names are:' + ', '.join(field for field in test_fields))
	            f.write('\n\nTotal rows of test are:\n') 
	            
	            for row in tmp_test_list: 
	            # parsing each column of a row 
	                for col in row:
	                    f.write("%s,"%col), 
	                    #f.write("%10s"%col), 
	                f.write('\n') 
        except Exception  as er:
                lgr.warn("     > %s,Write error, test case tuples. ..",str(er))        
        #reset counters        
        self.reset()         
        return            

    def Coverage_of_pair (self,function_code,test_field,test_fields,tmp_list_of_case,t,dir="coverage"):
        """
         this method write results test case and  Coverage  "{:.1%}".format(0.1234)-> '12.3%'. *.csv for test 2-way field '.
         t=256 in field one byte, t=65535 for two byte,
         .append('add_and_qua') case fuzz_session.priority==3:
        """
        rows_of_cover=[]
        test_fields =[x for x in test_fields if x != 'Combinatorial' and x != '2-way']
        if fuzz_session.priority==3:
            test_fields.append('add_and_qua') 
        fields = ['field', 'valid','invalid', 'total coverage % ' ]
        csvfile = log_dir+dir+'/coverage_of_fields_pair_FC%s.csv' %(function_code)

        if not os.path.exists(log_dir+dir):os.makedirs(log_dir+dir)       	 
        elif os.path.exists(log_dir+csvfile):
            lgr.warn("     > file name exist ..rename")
            os.rename(log_dir+csvfile, log_dir+csvfile_bak)
        else:
            lgr.info("    > Write coverage of pairs..")
        
        for i, sublist in enumerate(tmp_list_of_case):
            # data rows of csv file //loop for list_of_case
            coverage=format(float(len(tmp_list_of_case))/t * 100,'.2f')  #total coverage=
            rows_of_cover.append ([test_fields[i],tmp_list_of_case[i][0],tmp_list_of_case[i][1],coverage])
            
        if test_field=='2-way' or test_field=='Combinatorial':
        
            try: 
	            with open(csvfile,"w") as f:
	                csvwriter = csv.writer(f)
	                f.write('\nMTF-Storm v1.0 python3 fuzzing run:\n')
	                f.write('\nDate of run:%s\n'%datetime.now())  
	                f.write('\nFC: %d (0x%02X)..,software under test: %s \n'%(function_code,function_code,log_dir))
	                f.write('column names are:' + ', '.join(field for field in fields))
	                f.write('\n\nCoverage for fields 2-way :' + ', '.join(field for field in test_fields))                
	                f.write('\n\n\t case of test are:\n\n')
	                #f.write('\n\n\tcase and coverage for field no:\n\n')
	                
	                for row in rows_of_cover[:10]:
	                # parsing each column of a row 
	                    for col in row: 
	                        f.write("\t%10s"%col), 
	                    f.write('\n')             
            except Exception  as er:                                                          
	            lgr.warn("     > %s,Write error, tcase and coverage ..",str(er))

        #reset counters        
        self.reset()          
        return     

    def Coverage (self,function_code,test_field,test_fields,valid,invalid,tmp_test_list,t,dir="coverage"):
        """
        this method write results  Coverage  "{:.1%}".format(0.1234)-> '12.3%'. *.csv for test single field '.
        t=256 in field one byte, t=65535 for two byte
        """
        test_fields =[x for x in test_fields if x != 'Combinatorial' and x != '2-way']
        fields = ['field', 'valid','invalid', 'total coverage % ' ]
        csvfile = log_dir+dir+'/coverage_of_fields_FC%s.csv' %(function_code) 
        
        if not os.path.exists(log_dir+dir):
             os.makedirs(log_dir+dir)
        elif os.path.exists(log_dir+csvfile):
            lgr.warn("     > file name exist ..rename")
            os.rename(log_dir+csvfile, log_dir+csvfile_bak)
        else:
            lgr.info("    > Write coverage single test..")
        
        coverage=format(float(len(tmp_test_list))/t * 100,'.2f')
        fuzz_session.rows_of_cover.append ([test_field,valid,invalid,coverage])
        if test_field==test_fields[-1] :
        
            try: 
	            with open(csvfile,"w") as f:                    
	                csvwriter = csv.writer(f)
	                f.write('\nMTF-Storm v1.0 python3 fuzzing run:\n')
	                #f.write('\nDate of run:%s\n'%ctime())
	                f.write('\nDate of run:%s\n'%datetime.now())
	                f.write('\nFC: %d (0x%02X)..,software under test: %s \n'%(function_code,function_code,log_dir))
	                f.write('column names are:' + ', '.join(field for field in fields))
	                f.write('\n\nCoverage for fields:' + ', '.join(field for field in test_fields))
	                f.write('\n\n\tcase and coverage for field no:\n\n')
	                
	                for row in fuzz_session.rows_of_cover[:10]:
	                # parsing each column of a row 
	                    for col in row: 
	                        f.write("\t%10s"%col), 
	                    f.write('\n')                    
            except Exception  as er:
	            lgr.warn("     > %s,Write error, file coverage ..",str(er))  #raise .raise WriteError('Coverage error')
	            
        #reset counters         
        self.reset()                                                                                    
        return     
