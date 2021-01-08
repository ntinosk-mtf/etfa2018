import functools
import operator
import os
import csv
import metacomm.combinatorics.all_pairs2
#import all_pairs
all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2

"""
Another demo of filtering capabilities.
Demonstrates how to use named parameters

15 (0x0F) Write Multiple Coils
 
*N = Quantity of Outputs / 8, if the remainder is different of 0-N = N+1

 Byte Count 1 Byte =N*
Outputs Value N* x 1 By
-------------------  "Contr.rules---------------------------------------

Byte Count == Quantity of Outputs % 8 + [Quantity of Outputs / 8]
and Outputs Value ==Quantity of Outputs/8


Test case Initializing quantity: 153
Test case Initializing byte_count: 47
Test case Initializing num_values: 193
PAIRWISE list Initializes
Test case Initializing : 29269

--------------------------------------------------

fc 16 (0x10) Write Multiple registers
contiguous registers (1 to 123 registers) in a
*N = Quantity of Registers

Quantity of Registers 2 Bytes 0x0001 to 0x007B
Byte Count (1 Byte): 2 x N*
Registers Value :N* x 2 Bytes value

------------------------"Contr." ..rules-----
lambda d: d["byte_count"] == 2*d["quantity"] and d["num_values"] == 2*d["quantity"]
lambda d: d["num_values"] % 2 == 0 

if byte_count (1,255) then
Test case Initializing quantity: 165
Test case Initializing byte_count: 256
Test case Initializing num_values: 183
PAIRWISE list Initializes
Test case Initializing : 42240


new
test case Initializing quantity: 165
Test case Initializing byte_count: 47
Test case Initializing num_values: 183
PAIRWISE list Initializes
Test case Initializing : 15840
PAIRWISE:list
15840



23 (0x17) Read/Write Multiple registers


0x0001 <=  Quantity of Read <=0x007D
AND
0x0001 <= Quantity of Write <= 0x0079
AND
Byte Count == Quantity of Write x 2

Write Byte Count 1 Byte 2 x N*
Write Registers Value N*x 2 Bytes
*N = Quantity to Write


java -jar acts.jar
or
java -Xms <initial heap size> -Xmx <max heap size> <options> -jar acts.j
laptop nw
/home/ntinosk/MTF_PROJECT/ACTS3_0/demo
use
f15.txt

[[Constraint]
-- this section is also optional
num_value!=quan/8
byte_count != (quan%8 )+ (quan / 8)

ACTS Test Suite Generation: Fri Mar 06 13:28:58 EET 2020
#  '*' represents don't care value 
# Degree of interaction coverage: 2
# Number of parameters: 3
# Maximum number of values per parameter: 193
# Number of configurations: 29405
quan,byte_count,num_value

time 2.694 sec

"""
max_address=40000
star_addre=20000
quantity=  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65530, 65531, 65532, 65533, 65534, 65535]
byte_count=[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]#test case per FC of length illegal message PDU
num_values=  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1436, 1437, 1438, 1439, 1440, 1441, 1442, 1443, 1444, 1445, 1446, 1447, 1448, 1449, 1450, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1459, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65533, 65534, 65535, 65536, 65537]


print "Test case Initializing quantity: %d" % len(quantity)
print "Test case Initializing byte_count: %d" % len(byte_count)
print "Test case Initializing num_values: %d" % len(num_values)
#

#na vgalo olous touw sindiasmouw poy einai address =valid, quantity=valid kai address+quant =valid
parameters = [ ( "quantity"
            ,  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65530, 65531, 65532, 65533, 65534, 65535]
             ),
            ( "byte_count", [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]            ), 
            ("num_values" #register value
            ,  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 244, 245, 246, 247, 248, 249, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1436, 1437, 1438, 1439, 1440, 1441, 1442, 1443, 1444, 1445, 1446, 1447, 1448, 1449, 1450, 1451, 1452, 1453, 1454, 1455, 1456, 1457, 1458, 1459, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65533, 65534, 65535, 65536, 65537]
            
             #[0, 1, 2, 3, 4, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 58, 59, 60, 61, 62, 63, 64, 65, 66, 67, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 250, 251, 252, 253, 254, 255, 256, 257, 258, 259, 506, 507, 508, 509, 510, 511, 512, 513, 514, 515, 1000, 1018, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1360, 1361, 1362, 1363, 1364, 1365, 1366, 1367, 1368, 1369, 1963, 1964, 1965, 1966, 1967, 1968, 1969, 1970, 1971, 1972, 1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002, 2003, 2004, 2042, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 3000, 3066, 3067, 3068, 3069, 3070, 3071, 3072, 3073, 3074, 3075, 4000, 4090, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 5000, 6000, 7000, 8000, 8186, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 9000, 10000, 11000, 12000, 13000, 14000, 15000, 16000, 16377, 16378, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 17000, 18000, 19000, 20000, 21000, 22000, 23000, 24000, 25000, 26000, 27000, 28000, 29000, 30000, 31000, 32000, 32760, 32761, 32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769
              # ]
            )           
            ]

def is_valid_combination( values, names ):

    dictionary = dict(zip( names, values ) )
    #print dictionary 
    """
    To prevent search for unnecessary items filtering function
    is executed with found subset of data to validate it.
    For example: n % 2 == 0 means n is exactly divisible by 2 and n % 2 != 0 means n is not exactly divisible by 2.
    Byte Count == Quantity of Outputs % 8 + [Quantity of Outputs / 8]
    """

    rules = [ 
            #lambda d: d["byte_count"] == (d["quantity"]%8 + d["quantity"] / 8)
            lambda d: d["byte_count"] == 2*d["quantity"] and d["num_values"] == 2*d["quantity"]                                 
            #,lambda d: d["num_values"] == d["quantity"]/8 #excludes them
            ,lambda d: d["num_values"] % 2 == 0             
                       
            
           
            ]
    
    for rule in rules:
        try:
            if rule(dictionary):
                return False
        except KeyError: pass
    
    return True
                  

print("PAIRWISE list Initializes")
if os.path.exists("pair_test.csv"):
    # read CSV file & load into list
    with open("pair_test.csv", 'r') as f:
        reader = csv.reader(f)
        pairwise_temp = list(reader)
        #convert all elements to nit
        pairwise = map(lambda line: [int(x) for x in line],pairwise_temp)
        
else:
        pairwise=list(all_pairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))
        #Sorting a list of lists in Python
        pairwise.sort(key = lambda row: (row[0],row[2]))

        with open("pair_test.csv","w") as f:
            wr = csv.writer(f)
            wr.writerows(pairwise)
        
#print "Test case Initializing : %d" % len(pairwise)
print "Test case Initializing : %d" % len(pairwise)
 
pairwise = all_pairs(
      [ x[1] for x in parameters ]
    , filter_func = lambda values: is_valid_combination( values, [ x[0] for x in parameters ] )
    )
p=list(all_pairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))
         
#print pairwise
print("PAIRWISE:list")
#print p
print len(p)
#

#edv syndiazo ola ta invalid (bvazi exo ta invalid mazi)
"""PAIRWISE:list
[18, 123, 5000], [17, 123, 5000], [16, 123, 5000], [11, 123, 5000], [10, 123, 5000], [9, 123, 5000], [8, 123, 5000],
 [4, 123, 5000], [3, 123, 5000], [2, 123, 5000], [1, 123, 5000], [0, 123, 5000], [5, 123, 1361], [6, 123, 1361], [7, 123, 1361], 
 [12, 123, 8191], [13, 123, 8191], [14, 123, 8191], [15, 123, 1361], [19, 123, 8191], [20, 123, 8191], [21, 123, 8191], 
 [27, 123, 8191], [28, 123, 8191], [29, 123, 1361], [132, 123, 1361], [133, 123, 1021], [253, 123, 5000], [254, 123, 8191], [255, 123, 8191], [260, 123, 5000], [261, 123, 8191], [509, 123, 1021], [510, 123, 1361], [511, 123, 5000], [516, 123, 1999], [517, 123, 1361], [1021, 123, 1361], [1022, 123, 8191], [1023, 123, 1361], [1028, 123, 2], [1029, 123, 1999], [1992, 123, 1021], [1999, 123, 1021], [2006, 123, 5000], [2007, 123, 8191], [2043, 123, 8191], [2044, 123, 5000], [2045, 123, 1361], [2046, 123, 1361], [2047, 123, 1361], [2048, 123, 5000], [2049, 123, 5000], [2050, 123, 5000], [2051, 123, 5000], [2052, 123, 5000], [2053, 123, 5000], [4091, 123, 5000], [4092, 123, 5000], [4093, 123, 5000], [4094, 123, 5000], [4095, 123, 5000], [4096, 123, 5000], [4097, 123, 8191], [4098, 123, 5000], [4099, 123, 5000], [4100, 123, 5000], [4101, 123, 5000], [5000, 123, 8191], [8187, 123, 1999], [8188, 123, 5000], [8189, 123, 5000], [8190, 123, 8191], [8191, 123, 5000], [8192, 123, 8191], [8193, 123, 5000], [8194, 123, 5000], [8195, 123, 5000], [8196, 123, 5000], [8197, 123, 5000], [10000, 123, 8191], [16379, 123, 5000], [16380, 123, 5000], [16381, 123, 5000], [16382, 123, 5000], [16383, 123, 5000], [16384, 123, 5000], [16385, 123, 5000], [16386, 123, 5000], [16387, 123, 5000], [16388, 123, 5000], [16389, 123, 5000], [32763, 123, 5000], [32764, 123, 5000], [32765, 123, 8191], [32766, 123, 5000], [32767, 123, 5000], [32768, 123, 5000], [32769, 123, 5000], [32770, 123, 5000], [32771, 123, 5000], [32772, 123, 5000], [32773, 123, 5000], [49152, 123, 8191], [57344, 123, 8191], [61440, 123, 8191], [63488, 123, 8191], [64512, 123, 8191], [65024, 123, 8191], [65280, 123, 8191], [65408, 123, 8191], [65472, 123, 8191], [65504, 123, 5000], [65530, 123, 5000], [65531, 123, 5000], [65532, 123, 5000], [65533, 123, 5000], [65534, 123, 5000], [65535, 123, 5000]]



"""
