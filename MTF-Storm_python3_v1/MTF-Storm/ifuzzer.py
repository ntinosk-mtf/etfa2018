#!/usr/bin/env python
# -*- coding: utf-8 -*-
# share a variable between two modules for print log 

import os
import csv
import fuzz_session
import numpy as np
import logging 
import logging.handlers as handlers

lgr=logging.getLogger('')


def Read_CSv_FC():
    """
    Read csv file for config
    return FCmergedlist (list of support FC)
    """
    FCmergedlist =[]
    FCValues0=[]
    FCValues1=[]
    
    try :
            values = csv.reader(open('search.csv', 'r'), delimiter='\t')
            #read 0 colume
            for row in values:
                  FCValues0.append(row[0])
                  FCValues1.append(row[1])
                     
            # pop header
            FCValues0.pop(0)    
            FCValues1.pop(0)              
            FCmergedlist = FCValues0 + FCValues1  #Merge list of FC                                          
            FCmergedlist = [_f for _f in FCmergedlist if _f] #remove all empty strings and dumple item
            FCmergedlist = list(set(FCmergedlist))                                                                            
            FCmergedlist = [int(i) for i in FCmergedlist]  #convert all strings in a list to ints and sort list
            FCmergedlist.sort()
            return FCmergedlist
            
    except IOError:
            lgr.error('No such file or directory: search.csv')
            sys.exit(1) 

                    
def change_test_format():
    """
    fuzz_session.priority==2 if only testing format message
    print (log) change next test FC or stop test_dumplicate_ADU
    print (log) change test Fuzz testing format  or return None
    e.g
    if fuzz_type=='test_illegal_len_PDU', log 'Fuzz test format message: attack interesting byte'
    """

    if fuzz_session.test_format==1 :#test_dumplicate_ADU,
        if fuzz_session.flag_test_dumplicate_ADU==False: #log, Fuzz testing format message: test_dumplicate_ADU
            lgr.info('\t > Fuzzing format message: %r'%fuzz_session.fp[0]); lgr.info('' )
            fuzz_session.flag_test_dumplicate_ADU=True

        elif len(fuzz_session.FC_dumplicate_ADU)==0 and fuzz_session.flag_test_dumplicate_ADU==True: 
            lgr.info('\t > Change fuzz testing in next FC')  
            lgr.info('' )
        else :pass    

    elif fuzz_session.test_format==2:# test attack_byte_PDU
        if fuzz_session.flag_test_illegal_len_PDU==False: #first rest
            lgr.info('\t > Fuzzing attack PDU: %r '%(fuzz_session.attack_byte_PDU[0]));lgr.info('' )         
            fuzz_session.flag_test_illegal_len_PDU=True #fuzz_session.flag_test_attack_randByte=False 

        elif fuzz_session.flag_test_attack_randByte==True  :
            lgr.info('\t > Fuzzing attack PDU: %r'%fuzz_session.attack_byte_PDU[0]);lgr.info('' )       
            fuzz_session.flag_test_attack_randByte=False
       
        elif  fuzz_session.flag_test_attack_inter_byte==True  :
            lgr.info('\t > Fuzzing attack PDU: %r'%fuzz_session.attack_byte_PDU[0]);lgr.info('' )       
            fuzz_session.flag_test_attack_inter_byte=False    

        elif fuzz_session.flag_test_formatremove==True  :
            lgr.info('\t > Fuzzing attack PDU: %r'%fuzz_session.attack_byte_PDU[0]);lgr.info('' )       
            fuzz_session.flag_test_formatremove=False
        else :pass    
        
    elif fuzz_session.test_format==0:
        if fuzz_session.flag_test_dumplicate_ADU==False: #log,Fuzz testing format message: test_dumplicate_ADU, first
            lgr.info('\t > Fuzzing format message: %r'%fuzz_session.fp[0]);lgr.info('' )
            fuzz_session.flag_test_dumplicate_ADU=True;fuzz_session.flag_test_illegal_len_PDU=False #not, log  Fuzz testing format message:'test_illegal_len_PDU' 

        elif len(fuzz_session.FC_dumplicate_ADU)==0 and fuzz_session.flag_test_dumplicate_ADU==True:  
            lgr.info('\t > Fuzzing format message: %r'%fuzz_session.fp[0]);lgr.info('' ) #log  Fuzzing format message: 'test_illegal_len_PDU'

        elif fuzz_session.flag_test_attack_randByte==True  :
            lgr.info('\t > Fuzzing attack PDU: %r'%fuzz_session.attack_byte_PDU[0]);lgr.info('' )       
            fuzz_session.flag_test_attack_randByte=False
       
        elif  fuzz_session.flag_test_attack_inter_byte==True  :
            lgr.info('\t > Fuzzing attack PDU: %r'%fuzz_session.attack_byte_PDU[0]);lgr.info('' )       
            fuzz_session.flag_test_attack_inter_byte=False    

        elif fuzz_session.flag_test_formatremove==True  :
            lgr.info('\t > Fuzzing attack PDU: %r'%fuzz_session.attack_byte_PDU[0]) ;lgr.info('' )     
            fuzz_session.flag_test_formatremove=False
        else :pass    
                           
    return None	                             


