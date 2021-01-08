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
"""
max_address=40000
star_addre=20000
quantity_write=  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65530, 65531, 65532, 65533, 65534, 65535]
byte_count=[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]#test case per FC of length illegal message PDU
num_value=  [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65530, 65531, 65532, 65533, 65534, 65535]



print "Test case Initializing quantity: %d" % len(quantity_write)
print "Test case Initializing byte_count: %d" % len(byte_count)
print "Test case Initializing num_values: %d" % len(num_value)

#na vgalo olous touw sindiasmouw poy einai address =valid , quantity=valid kai address+quant =valid
parameters = [           
             ( "quantity_write" 
               , quantity_write
               #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65530, 65531, 65532, 65533, 65534, 65535]
                )            
             , ( "byte_count" 
               , byte_count
               #[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255
             ) 
             
             , ( "num_value"
               , num_value
               #[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 134, 251, 252, 253, 254, 255, 256, 257, 258, 259, 260, 261, 507, 508, 509, 510, 511, 512, 513, 514, 515, 516, 517, 1019, 1020, 1021, 1022, 1023, 1024, 1025, 1026, 1027, 1028, 1029, 2043, 2044, 2045, 2046, 2047, 2048, 2049, 2050, 2051, 2052, 2053, 4091, 4092, 4093, 4094, 4095, 4096, 4097, 4098, 4099, 4100, 4101, 5000, 8187, 8188, 8189, 8190, 8191, 8192, 8193, 8194, 8195, 8196, 8197, 10000, 16379, 16380, 16381, 16382, 16383, 16384, 16385, 16386, 16387, 16388, 16389, 20000, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 32770, 32771, 32772, 32773, 65530, 65531, 65532, 65533, 65534, 65535]
            )
            ]

def is_valid_combination( values, names ):

    dictionary = dict(zip( names, values ) )
    #print dictionary 
    """
    To prevent search for unnecessary items filtering function
    is executed with found subset of data to validate it.
    """

    rules = [ 
            
             lambda d: d["byte_count"] == 2*d["quantity_write"] and d["num_value"] == 2*d["quantity_write"]
             ,lambda d: d["num_value"] % 2 == 0              
            ]
    
    for rule in rules:
        try:
            if rule(dictionary):
                return False
        except KeyError: pass
    
    return True
                  

print("PAIRWISE list Initializes")
if os.path.exists("pair_test23.csv"):
    # read CSV file & load into list
    with open("pair_test23.csv", 'r') as f:
        reader = csv.reader(f)
        pairwise_temp = list(reader)
        #convert all elements to nit
        pairwise = map(lambda line: [int(x) for x in line],pairwise_temp)
        
else:
        pairwise=list(all_pairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))

        pairwise.sort(key = lambda row: row[0])

        with open("pair_test23.csv","w") as f:
            wr = csv.writer(f)
            wr.writerows(pairwise)
        
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
print p
print len(p)
#

#edv syndiazo ola ta invalid (bvazi exo ta invalid mazi)
"""PAIRWISE:list
[[1001, 130, 1024], [1002, 345, 1024], [2000, 4000, 1024], [2000, 5600, 1024], [1002, 65000, 1024], [1001, 32000, 1024], 
[1001, 65000, 1024], [1002, 5600, 1024], [2000, 65000, 1024], [2000, 32000, 1024], [1002, 32000, 1024], [1001, 5600, 1024],
[1001, 4000, 1024], [1002, 4000, 1024], [2000, 130, 1024], [2000, 345, 1024], [1002, 130, 1024], [1001, 345, 1024]]
"""
#periptoso poy valid address kai invalid quantity pos ??