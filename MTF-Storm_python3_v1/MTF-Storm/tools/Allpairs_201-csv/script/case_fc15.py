import functools
import operator
import os
import csv
#Use allpairspy, https://github.com/thombashi/allpairspy
from allpairspy import AllPairs
import csv

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
or d["num_values"] == d["byte_count"] 


Test case Initializing quantity: 192
Test case Initializing byte_count: 60
Test case Initializing num_values: 183
PAIRWISE list Initializes
Test case Initializing : 

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

#lgr.info('quantity_of_x_list for pairwise test : %s' %fuzz_session.quantity_of_x_list_coil_cart)
#lgr.info('num quantity_of_x_list for pairwise test : %d' %len(fuzz_session.quantity_of_x_list_coil_cart))
quantity= [0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 1966, 1967, 1968, 1969, 1998, 1999, 2000, 2001, 2047, 2048, 2049, 4095, 4096, 4097, 5000, 8191, 8192, 8193, 10000, 16383, 16384, 16385, 20000, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
byte_count= [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 65, 66, 67, 68, 69, 77, 78, 79, 80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90, 91, 92, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 247, 248, 249, 250, 251, 252, 253, 254, 255]

#test case per FC of length illegal message PDU
num_values=[ 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 1440, 1442, 1444, 1446, 1448, 1450, 1452, 1454, 1456, 1458, 1460, 1462, 1464, 1466, 1468, 1470, 1472, 1474, 1476, 1478, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65533, 65534, 65535, 1, 2, 3, 4, 5, 8, 16, 32, 63, 64, 65, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 245, 247, 249, 250]

print ("Test case Initializing quantity: %d" % len(quantity))
print ("Test case Initializing byte_count: %d" % len(byte_count))
print ("Test case Initializing num_values: %d" % len(num_values))
#

parameters = [ ( "quantity" ,  quantity),
            ( "byte_count",  byte_count), 
            ("num_values" , num_values)           
            ]

def is_valid_combination( values, names ):

    dictionary = dict(zip( names, values ) )
    #print dictionary 
    """
    To prevent search for unnecessary items filtering function
    is executed with found subset of data to validate it.
    For example: n % 2 == 0 means n is exactly divisible by 2 and n % 2 != 0 means n is not exactly divisible by 2.
    Byte Count == Quantity of Outputs % 8 + [Quantity of Outputs / 8]
    from test_field-PDU.py
    lambda d: d["byte_count"] == (d["quantity"]%8 + d["quantity"] // 8)                             
                ,lambda d: d["num_values"] == d["quantity"]//8         
    
    old
    rules = [ 
            lambda d: d["byte_count"] == (d["quantity"]%8 + d["quantity"] // 8) ==d["num_values"]                                           
            #,lambda d: d["num_values"] == d["byte_count"] #excludes them
            #
            ,lambda d: d["byte_count"] -20 <= d["num_values"] <= d["byte_count"] -20                                
            ]
    """
    rules = [ 
                lambda d: d["byte_count"] == (d["quantity"]%8 + d["quantity"] // 8)                             
                ,lambda d: d["num_values"] == d["quantity"]//8                             
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
        pairwise=list(AllPairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))
        #Sorting a list of lists in Python
        pairwise.sort(key = lambda row: (row[0],row[1]))

        with open("pair_test.csv","w") as f:
            wr = csv.writer(f)
            wr.writerows(pairwise)
        

 
pairwise = AllPairs(
      [ x[1] for x in parameters ]
    , filter_func = lambda values: is_valid_combination( values, [ x[0] for x in parameters ] )
    )
p=list(AllPairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))
         
print ("Test case Initializing : %d" % len(p))
print("PAIRWISE:list")
print (len(p))

