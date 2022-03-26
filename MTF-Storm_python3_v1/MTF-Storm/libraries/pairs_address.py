
#!/usr/bin/env python
# -*- coding: utf-8 -*-

import sys
import os
import csv
import fuzz_session
import modbus_tk.utils
from utils_b import *
import logging.handlers as handlers
from defines import *

logger = modbus_tk.utils.create_logger("console") #create logger- 
lgr=logging.getLogger('')

#-----------------------------------------------------------------------------------------------------------------  
# This class fuzz testing  a field of PDU Modbus protocol and illegal packet format (dumplicate ADU/PDU)
# Configuration for fuzzing not specification message len and Dumplicate (ADU address x quantity_of)
# PAIRWISE  test for FC 01 ,02 ,03 ,04 , address +quantity bount + 20   
# program to find all  pairs in both arrays whose  sum is equal to given value x 
    
# cross  pairs parameter of FC to find all  pairs in both arrays whose 
# sum is equal to given value x nd y
# Create a 2D Numpy Array like Matrix
# electing random rows from a NumPy array results in a new array with a specified number of rows from the original.
# All rows are equally likely to be selected. For example, randomly selecting 2 rows from [[a, a, a], [b, b, b],..., 
# Use numpy.random.choice(a, size=k, replace=False) 
# to generate a list of k random indices without repetition from a NumPy array with a rows. 
 
# number_of_rows = an_array.shape[0]
# random_indices = np.random.choice(number_of_rows, size=2, replace=False
# random_rows = an_array[random_indices, :]
#----------------------------------------------------------------------------------------------------------------------

class pairs_address_qua(object):
    output_values=[]    
       
    def __init__(self ):
        """
        Constructor. Set the Initializing settings
        dir=./csvtestPDU def save dir
        self.in_lis , interesting value 
        create for FC01,..FC04..FC05 FC06 "./csvtestPDU" def save dir .csv file fot test
        self.dir="./csvtestPDU"
        self.pathCSV=self.dir+"/FC0%d_pair.csv"
        create for FC01-FC04.. dir="csvtestformat_test_format" def save dir .csv file fot test
        self.dirformat="./csvtestformat"
        self.pathCSVformat=self.dirformat+"/FC0%d_pair.csv"
        n range memory -+20  self.b=20
        self.randomrows=0.9,selecting random rows of matrix
                  
        """ 

        self.b=20
        self.max_num =65536
        self.bountary=256
        self.randomrows=0.9
        self.dir="./csvtestPDU"
        self.pathCSV=self.dir+"/FC0%d_pair.csv"

        self.dirformat="./csvtestformat"
        self.pathCSVformat=self.dirformat+"/FC0%d_pair.csv"

        self.in_lis=[0,1,127,128,129, 255, 256, 257, 511, 512, 513, 1000, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770,
                       32771, 32772, 32773 ,32775, 0xFFFF-5, 0xFFFF-4, 0xFFFF-3,0xFFFF-2, 0xFFFF-1, 0xFFFF]
        
        #interest hex value , -256 +-2 , 65535 -1 -2
        #[0, 1, 32767, 32768, 32769, 255, 256, 254, 65533, 65535, 65534,....-256]
        if len(self.output_values)==0:
           
            self.output_values.append (0);self.output_values.append (1)
            self.output_values.append (self.max_num -1)           #65535
            self.output_values.append (self.max_num -2)
            self.output_values.append (self.max_num -3)
            self.output_values.append (self.max_num -4)
            self.output_values.append (self.max_num -5)
            self.output_values.append ((self.max_num // 2)-2)     
            self.output_values.append ((self.max_num // 2)-1)     #32767
            self.output_values.append (self.max_num // 2)         #32768
            self.output_values.append ((self.max_num // 2)+1)     #32769
            self.output_values.append ((self.max_num // 2)+2)     
            self.output_values.append ((self.max_num // 256)-1)   #
            self.output_values.append (self.max_num // 256)       #256
            self.output_values.append ((self.max_num // 256)-2)   #254
            
            self.output_values.append (-(self.max_num // 256)+2)    #-258 
            self.output_values.append (-(self.max_num // 256)+1)    #-255
            self.output_values.append (-(self.max_num // 256))      #-256
            self.output_values.append (-(self.max_num // 256)-1)    #-257
            self.output_values.append (-(self.max_num // 256)-2)    #-258   

    def pair(self,function_code,l1,l2,maxaddress,minaddress):
        """ 
        PAIRWISE test -create for FC01..FC04.. "./csvtestPDU" def save dir .csv file fot test
        class fuzz testing  a field of PDU set PAIRWISE test Initializes from CSV for address vs quantity
        and FC05 FO6 for address vs value
        """        
        self.dir = os.path.normpath(self.dir)  
        if not os.path.exists(self.dir):os.makedirs(self.dir)   # Create a folder for the logfiles.
        try:
        
            if os.path.exists(self.pathCSV%function_code):
                # read CSV file & load into list               
                with open(self.pathCSV%function_code,'r') as f:                  # self.pathCSV=self.dir+"/FC0%d_pair.csv"
                    reader = csv.reader(f); pairwise_temp = list(reader)                   
                    #convert all elements to Init
                    pairwise = np.array(list([[int(x) for x in line] for line in pairwise_temp]))
                    
            else:
                    lgr.warn("not file CSV.......")                  
                    
                    if function_code in (1,2,3,4):pairwise=self.findPairs(l1, l2, maxaddress,minaddress)
                    elif function_code in (5,6):pairwise=self.findPair_wsingle(l1, maxaddress,minaddress)
                    with open(self.pathCSV%function_code,"w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table ..")
                        wr.writerows(pairwise)                                                                                                      
                        #multiple statements on the same line            
        except IOError :lgr.exception("");  pairwise=[]
               
        if len(pairwise)==0:
                raise ValueError ('no data')    
        
        lgr.info('Test case Initializing for FC0%d --------- : %d '% (function_code,np.size(pairwise, 0)))        
        return np.array(pairwise)

    def pair_format_dumpl(self,function_code,l1,l2,maxaddress,minaddress):
        """ 
         create for FC01-FC04.. dir="csvtestformat_test_format" def save dir .csv file fot test
         illegal packet format (dumplicate ADU/PDU) len and Dumplicate (ADU address x quantity_of)
         Set PAIRWISE test Initializes from CSV for address vs quantity
         Class fuzz testing  illegal packet format (dumplicate ADU/PDU)
         set init 
         self.pathCSVformat=self.dirformat+"/FC0%d_pair.csv"
        """        
        self.dirformat = os.path.normpath(self.dirformat)
        # Create a folder for the logfiles.
        if not os.path.exists(self.dirformat):os.makedirs(self.dirformat)
        try:
        
            if os.path.exists(self.pathCSVformat%function_code):
                # read CSV file & load into list               
                with open(self.pathCSVformat%function_code,'r') as f:
                    reader = csv.reader(f); pairwise_temp = list(reader)                   
                    #convert all elements to Init
                    pairwise = np.array(list([[int(x) for x in line] for line in pairwise_temp]))
                    
            else:
                    lgr.warn("not file CSV.......in %s"%dir)                  
                    pairwise=self.findPairs(l1, l2, maxaddress,minaddress)
                    with open(self.pathCSVformat%function_code,"w") as f:
                        wr = csv.writer(f)
                        lgr.info("Write csv file np table ..")
                        wr.writerows(pairwise)                                                                                                      
                        #multiple statements on the same line            
        except IOError :lgr.exception("");  pairwise=[]
               
        if len(pairwise)==0:
                lgr.warn("-------  file not data   ..return");return np.array(pairwise)
        
        lgr.info('Test case Initializing for FC0%d --------- : %d '% (function_code,np.size(pairwise, 0)))        
        return np.array(pairwise)


    def findPairs(self,list1, list2, max_address,min_address):
        """
        Create a 2D Numpy Array like Matrix
        Write a NumPy program to add a new row to an empty numpy array.
        arr = np.empty((0,3), int)
        arr = np.append(arr, np.array([[10,20,30]]), axis=0)
        arr = np.append(arr, np.array([[40,50,60]]), axis=0)

        Restrictions
        list1[i] + list2[j]) <max_address+512 
        list1[i]<max_address
        Selecting random rows of matrix1 (all invalid),def=number_of_rows, from pair in in_lis
        self.in_lis=[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF, 0xFFFF+1,
                       0xFFFF+2]

        Sample Output:
        [[10 20 30]
        [40 50 60]]
        """ 
        
        n = len(list1); m = len(list2)    
        # empty numpy array.
        matrixArr1=np.empty((0,2), int);matrixArr=np.empty((0,2), int)
        
        for i in range(0, n): 
            for j in range(0, m): 
                if list1[i]<max_address :
                    if (max_address-self.bountary <(list1[i] + list2[j]) <max_address+self.bountary) or  (min_address-self.bountary <(list1[i] + list2[j]) <min_address+self.bountary):
                        matrixArr = np.append(matrixArr,[[list1[i],list2[j]]],axis = 0)
                else :
                    if  list1[i] in self.in_lis :
                        if list2[j] in self.in_lis :
                            matrixArr1 = np.append(matrixArr1,[[list1[i],list2[j]]],axis = 0)

        numOfColumns = np.size(matrixArr, 1); numOfRows = np.size(matrixArr, 0)
        lgr.info('Number of Rows matrixArr  in range memory -+%d ): %d ', numOfRows,self.bountary)
        numOfRows1 = np.size(matrixArr1, 0)
        lgr.info('Number of Rows matrixArr1 > max_address +%d : %d', numOfRows1,self.bountary)

        #Selecting random rows of matrix1 (all invalid),def=number_of_rows
        number_of_rows = matrixArr1.shape[0]
        size=int((number_of_rows*self.randomrows))
        if size >1000: size=999
        
        random_indices = np.random.choice(number_of_rows, size, replace=False)
        random_rows = matrixArr1[random_indices, :]
        #lgr.info('Number of Rows randoms pair: %d ', rowmatrix3)  
        #append a NumPy array to a NumPy array
        lgr.info ('Matrix3 array append random_indices :%d',size)
        matrix3=np.concatenate((matrixArr, random_rows))
        rowmatrix3 = np.size(matrix3, 0)
        lgr.info('Number of Rows: %d ', rowmatrix3)
        return matrix3


    def findPair_wsingle(self,list1, max_address,min_address):
        """
        set PAIRWISE test Initializes from CSV FC05 FO6 for address vs value
        Create a 2D Numpy Array like Matrix
        Write a NumPy program to add a new row to an empty numpy array.
        arr = np.empty((0,3), int)
        arr = np.append(arr, np.array([[10,20,30]]), axis=0)
        arr = np.append(arr, np.array([[40,50,60]]), axis=0)

        Restrictions
       
        list1[i]<max_address
        Selecting random rows of matrix1 (out of limits address interesting value )or matrix2 (in limits address interesting value )

        self.in_lis=[128, 255, 256, 257, 511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1, 0xFFFF]

        Sample Output:
        [[10 20 30]
        [40 50 60]]

        list1=fuzz_session.fuzz_addre_HO_REG_cart or fuzz_session.quantity_of_x_list_coil_cart
        list2 =self.output_values
        """ 
        
        list2 =self.output_values                
        n = len(list1); m = len(list2)    
        # empty numpy array.
        matrixArr1=np.empty((0,2), int);matrixArr=np.empty((0,2), int); matrixArr2=np.empty((0,2), int)
        #out/in of limits address interesting value 
        for i in range(0, len(self.in_lis)):
            for j in range(0, m):
                if  self.in_lis[i] > max_address or self.in_lis[i]<min_address :
                        matrixArr1 = np.append(matrixArr1,[[self.in_lis[i],list2[j]]],axis = 0) #out of limits address 
                else :  matrixArr2 = np.append(matrixArr2,[[self.in_lis[i],list2[j]]],axis = 0) # in limits address interesting value 
                        
        #bountary of limits +-20 =self.b
        for j in range(0, m):
             for k in range(1, self.b):
                if self.max_num >(max_address-k)>0:matrixArr =np.append(matrixArr,[[(max_address-k),list2[j]]],axis = 0)
                if self.max_num >(max_address+k)>0 : matrixArr =np.append(matrixArr,[[(max_address+k),list2[j]]],axis = 0)
                if  self.max_num >(min_address+k)>0 :matrixArr =np.append(matrixArr,[[(min_address+k),list2[j]]],axis = 0)
                if self.max_num >(min_address-k)>0:matrixArr =np.append(matrixArr,[[(min_address-k),list2[j]]],axis = 0)
                    
        numOfColumns = np.size(matrixArr, 1); numOfRows = np.size(matrixArr, 0)
        lgr.info('Number of Rows matrixArr in range memory -+20): %d ', numOfRows)
        numOfRows1 = np.size(matrixArr1, 0)
        lgr.info('Number of Rows matrixArr1 out of limits address: %d', numOfRows1)
        numOfRows2 = np.size(matrixArr2, 0)
        lgr.info('Number of Rows matrixArr2 in limits address: %d', numOfRows2)

        #Selecting random rows of matrix1 (all invalid),def=number_of_rows
        number_of_rows = matrixArr1.shape[0]
        #self.randomrows=0.9
        size=int((number_of_rows*self.randomrows))
        if size >1000: size=999
        random_indices = np.random.choice(number_of_rows, size, replace=False)
        random_rows1 = matrixArr1[random_indices, :]

        #Selecting random rows of matrix2 (in limits address:),def=number_of_rows
        number_of_rows = matrixArr2.shape[0]
        size=int((number_of_rows*self.randomrows))
        if size >1000: size=999
        random_indices = np.random.choice(number_of_rows, size, replace=False)
        random_rows2 = matrixArr2[random_indices, :]

        #append a NumPy array to a NumPy array
        lgr.info ('Matrix3 array append random_indices :%d',size)
        matrix3=np.concatenate((matrixArr, random_rows1,random_rows2))
        rowmatrix3 = np.size(matrix3, 0)
        lgr.info('Number of Rows: %d ', rowmatrix3)
        #return matrix3
        return (matrix3[np.argsort(matrix3[:, 0])])
    
