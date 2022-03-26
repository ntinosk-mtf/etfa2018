import functools
import operator
import os
import csv
from allpairspy import AllPairs


""" Read File Record Request FC : 20   file_number: 0-0xffff  record_number:0-0x270f  record_length=N 2 byte
    Returns the contents of registers in Extended Memory file (6XXXXX) references
    The function can read multiple groups of references. The groups can be separate
    (non–contiguous), but the references within each group must be sequential.
    :params reference_type: Defaults to 0x06 (must be)
    :params file_number: Indicates which file number we are reading (0,10)
    :params record_number: Indicates which record in the file -(starting address)
    :params record_data: The actual data of the record - 
    :params record_length: The length in registers of the record -(register count)
    :params response_length: The length in bytes of the record
"""    
Byte_count =[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]
Reference_Type =[0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]
#fix  10+-
File_number =[0, 1, 2, 3, 4, 5, 7, 8, 9, 10,11,12,13,14,15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 10000, 20000, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
Record_number =[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 9993, 9994, 9995, 9996, 9997, 9998, 9999, 10000, 10001, 10002, 10003, 10004, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]
Record_length =[0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 126, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, 1024, 1025, 2047, 2048, 2049, 4095, 4096, 4097, 8191, 8192, 8193, 16383, 16384, 16385, 32767, 32768, 32769, 65471, 65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65530, 65531, 65532, 65533, 65534, 65535]

"""
results
Test case Initializing Byte_count: 60
Test case Initializing Reference_Type: 60
Test case Initializing File_number: 70
Test case Initializing Record_number: 75
Test case Initializing Record_length: 74

len =5956
"""

print ("Test case Initializing Byte_count: %d" % len(Byte_count))
print ("Test case Initializing Reference_Type: %d" % len(Reference_Type))
print ("Test case Initializing File_number: %d" % len(File_number))
print ("Test case Initializing Record_number: %d" % len(Record_number))
print ("Test case Initializing Record_length: %d" % len(Record_length))

#na vgalo olous touw sindiasmouw poy einai address =valid , quantity=valid kai address+quant =valid
parameters = [           
             ( "Byte_count" , Byte_count)            
             , ( "Reference_Type", Reference_Type)            
             , ( "File_number", File_number)
             , ( "Record_number", Record_number)
             , ( "Record_length", Record_length)
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
if os.path.exists("pair_test20.csv"):
    # read CSV file & load into list
    with open("pair_test20.csv", 'r') as f:
        reader = csv.reader(f)
        pairwise_temp = list(reader)
        #convert all elements to nit
        pairwise = map(lambda line: [int(x) for x in line],pairwise_temp)
        #pairwise.sort(key = lambda row: (row[0],row[1],row[2]) )#demo python3 
        
else:
        pairwise=list(AllPairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))

        #pairwise.sort(key = lambda row: row[0])
        pairwise.sort(key = lambda row: (row[0],row[1],row[2]) )#demo python3 

        with open("pair_test20.csv","w") as f:
            wr = csv.writer(f)
            wr.writerows(pairwise)
        
#print ("Test case Initializing : %d" % len(pairwise))
 
pairwise = AllPairs(
      [ x[1] for x in parameters ]
    , filter_func = lambda values: is_valid_combination( values, [ x[0] for x in parameters ] )
    )
p=list(AllPairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))
         
#print pairwise
print("PAIRWISE:list")
#print p
print ("len =%d " %len(p))
#

#edv syndiazo ola ta invalid (bvazi exo ta invalid mazi)
"""PAIRWISE:list
[[1001, 130, 1024], [1002, 345, 1024], [2000, 4000, 1024], [2000, 5600, 1024], [1002, 65000, 1024], [1001, 32000, 1024], 
[1001, 65000, 1024], [1002, 5600, 1024], [2000, 65000, 1024], [2000, 32000, 1024], [1002, 32000, 1024], [1001, 5600, 1024],
[1001, 4000, 1024], [1002, 4000, 1024], [2000, 130, 1024], [2000, 345, 1024], [1002, 130, 1024], [1001, 345, 1024]]
"""
#periptoso poy valid address kai invalid quantity pos ??