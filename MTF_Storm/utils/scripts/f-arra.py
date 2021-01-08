# Python 2-3 program to find all  
# pairs in both arrays whose  
# sum is equal to given value x 
  
# Function to print all pairs 
# Checking if 4 exists in list  
# using in 
#if (4 in test_list): 
#    print ("Element Exists")  
# in both arrays whose sum is 
# equal to given value x
# Create a 2D Numpy Array like Matrix
#    matrixArr = numpy.array( [ [1, 2, 3],
#                              [ 4, 5, 6] ])
 
#    print('Contents of 2D Numpy Array : ')
#    print(matrixArr)
'''
Get number of rows and columns of this 2D numpy array:

Python

# get number of rows in 2D numpy array
numOfRows = np.size(arr2D, 0)
# get number of columns in 2D numpy array
numOfColumns = np.size(arr2D, 1)
print('Number of Rows : ', numOfRows)
print('Number of Columns : ', numOfColumns)

# get number of rows in 2D numpy array
numOfRows = np.size(arr2D, 0)
 
# get number of columns in 2D numpy array
numOfColumns = np.size(arr2D, 1)
 
print('Number of Rows : ', numOfRows)
print('Number of Columns : ', numOfColumns)

print np.size(matrixArr)


Selecting random rows from a NumPy array results in a new array with a specified number of rows from the original.
 All rows are equally likely to be selected. For example, randomly selecting 2 rows from [[a, a, a], [b, b, b],..., 
 [z, z, z]] could result in [[r, r, r], [b, b, b]].
 Use numpy.random.choice(a, size=k, replace=False) 
 to generate a list of k random indices without repetition from a NumPy array with a rows. 
 Subset the array with this list to select k random rows.
 number_of_rows = an_array.shape[0]
random_indices = np.random.choice(number_of_rows, size=2, replace=False
random_rows = an_array[random_indices, :]
print(random_rows)


Append a NumPy array to a NumPy array
n [2]: a = np.array([[1, 2, 3], [4, 5, 6]])
In [3]: b = np.array([[9, 8, 7], [6, 5, 4]])
In [4]: np.concatenate((a, b))

'''
import numpy as np

a = np.array([[1,1],[4,1]])
a=np.append(a, [[7,8]],axis = 0)  

print 'First array:'
#print np.append(a, [[7,8,9]],axis = 0)  
print a 
print '\n' 

def findPairs(arr1, arr2, n, m, x): 
    #list=range(1,4)
    matrixArr = np.array([[1,1],[4,1]])
    matrixArr1 = np.array([[1,1],[4,1]])
    for i in range(0, n): 
        for j in range(0, m): 
            #if (arr1[i] + arr2[j] in range(1980,2020)) or (arr1[i] + arr2[j]) <3000 :
            if (arr1[i] + arr2[j]) >2048 : 
                matrixArr = np.append(matrixArr,[[arr1[i],arr2[j]]],axis = 0)
                #print('Contents of the Numpy Array arr : ', matrixArr)
            else : 
                matrixArr1 = np.append(matrixArr1,[[arr1[i],arr2[j]]],axis = 0)

    print(matrixArr)
    print(matrixArr1)
    #numOfColumns = np.size(matrixArr, 1)
    numOfRows = np.size(matrixArr, 0)
    print('Number of Rows : ', numOfRows)
    numOfRows1 = np.size(matrixArr1, 0)
    print('Number of Rows : ', numOfRows1)

    #Selecting random rows
    number_of_rows = matrixArr1.shape[0]
    random_indices = np.random.choice(number_of_rows, size=100, replace=False)
    random_rows = matrixArr1[random_indices, :]
    print(random_rows)

    #append a NumPy array to a NumPy array
    print 'matrix3 array append '

    matrix3=np.concatenate((matrixArr1, random_rows))
    print(matrix3)
    rowmatrix3 = np.size(matrix3, 0)
    print('Number of Rows : ', rowmatrix3)



# Driver code 
arr1 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29,132, 133, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535] 
 
arr2 = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29,132, 133, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1989, 1990, 1991, 1992, 1993, 1994, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2005, 2006, 2007, 2008, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535] 
 
n = len(arr1) 
m = len(arr2) 
x = 8
findPairs(arr1, arr2, n, m, x) 