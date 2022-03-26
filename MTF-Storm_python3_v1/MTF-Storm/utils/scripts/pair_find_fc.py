
import operator
import os
import csv
import numpy as np

#----------------------------------------------------------------------------#  
#This class fuzz testing  a field of PDU Modbus protocol
#cross  pairs parameter of FC to find all  pairs in both arrays whose 
#sum is equal to given value x nd y
#Create a 2D Numpy Array like Matrix
#----------------------------------------------------------------------------#
class pairs_address_qua(object):    
    
    def __init__(self ):
        
        """Constructor. Set the Initializing settings
           
         """ 

    def pair(self,function_code,l1,l2,address):

        """ PAIRWISE test -create for .. 
        """ 
        print("PAIRWISE list Initializes")
        
        try:
            
            if os.path.exists("FC0%d_pair.csv"%function_code):
                    # read CSV file & load into list
                    with open("FC0%d_pair.csv"%function_code,'r') as f:
                        reader = csv.reader(f)
                        #pairwise = list(reader)
                        pairwise_temp = list(reader)
                        #convert all elements to Init
                        pairwise = np.array(list(map(lambda line: [int(x) for x in line],pairwise_temp)))
                        
            else:
                        print("-------------not file csv.. ..")
                        if function_code==3:
                           pairwise=self.findPairs(l1, l2, address)
                           with open("FC0%d_pair.csv"%function_code,"w") as f:
			               wr = csv.writer(f)
			               print("Write csv file np table ..")
			               wr.writerows(pairwise)
			                                                                     
                        elif  function_code==2:
                            print("PAIRWISE list Initializes--fc2")
                            pairwise=self.findPairs(l1, l2, address)

                        #multiple statements on the same line
                        else : print("except");  pairwise=[]
                              
  
                                                
        except IOError :
                #print.exception('')
                pairwise=[]
                print("except")

        if len(pairwise)==0:
                raise ValueError ('no data')    
        

        print('--------- Test case Initializing --------- : %d '% len(pairwise))          
        return np.array(pairwise)


    #----------------------------------------------------------------------------------------------------#            
    # PAIRWISE  test for FC 01 ,02 ,03 ,04 , address +quantity bount + 20   
    # program to find all  pairs in both arrays whose  sum is equal to given value x 
    # Create a 2D Numpy Array like Matrix
    # Write a NumPy program to add a new row to an empty numpy array.
    # arr = np.empty((0,3), int)
    # arr = np.append(arr, np.array([[10,20,30]]), axis=0)
    # arr = np.append(arr, np.array([[40,50,60]]), axis=0)
    # Sample Output:
    # [[10 20 30]
    # [40 50 60]]
   
    #----------------------------------------------------------------------------------------------------# 
    def findPairs(self,list1, list2, max_address): 
    	n = len(list1) 
        m = len(list2)            
        # empty numpy array.
        matrixArr1=np.empty((0,2), int)
        matrixArr=np.empty((0,2), int)

        print('Contents of the Numpy Array arr : ', matrixArr)

        for i in range(0, n): 
            for j in range(0, m): 
                if (list1[i] + list2[j]) <max_address+1024 : 
                    matrixArr = np.append(matrixArr,[[list1[i],list2[j]]],axis = 0)
                    #print('Contents of the Numpy Array arr : ', matrixArr)
                else : 
                    matrixArr1 = np.append(matrixArr1,[[list1[i],list2[j]]],axis = 0)

        #lgr.info(matrixArr)
        #lgr.info(matrixArr1)
        print matrixArr 
        numOfColumns = np.size(matrixArr, 1)
        numOfRows = np.size(matrixArr, 0)
        print('Number of Rows matrixArr: %d ', numOfRows)
        numOfRows1 = np.size(matrixArr1, 0)
        print('Number of Rows matrixArr1: %d', numOfRows1)

        #Selecting random rows of matrix1 (all invalid),def=number_of_rows
        number_of_rows = matrixArr1.shape[0]
        size=(number_of_rows*0.25)
        if size >1000: size=1000
            
        random_indices = np.random.choice(number_of_rows, size, replace=False)
        random_rows = matrixArr1[random_indices, :]
        #lgr.info(random_rows)

        #append a NumPy array to a NumPy array
        print('matrix3 array append %d',size)

        matrix3=np.concatenate((matrixArr, random_rows))
        #print(matrix3)
        rowmatrix3 = np.size(matrix3, 0)
        print('Number of Rows : %d ', rowmatrix3)
        return matrix3

#Driver code 
arr1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29,132, 133, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535] 
 
arr2 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29,132, 133, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535] 
 
#n = len(arr1) 
#m = len(arr2) 

q=pairs_address_qua()

COIL=q.pair(3,arr1,arr2,2048)
print(COIL)
print('--------- Test case Initializing --------- : %d '% len(COIL))
#a.tolist()
#print('--------- Test case Initializing --------- : %r '% COIL.tolist())

rowcoil = np.size(COIL, 0)





