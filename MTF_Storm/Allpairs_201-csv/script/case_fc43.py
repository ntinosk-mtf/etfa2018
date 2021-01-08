import functools
import operator
import os
import csv
import metacomm.combinatorics.all_pairs2
all_pairs = metacomm.combinatorics.all_pairs2.all_pairs2

"""
Another demo of filtering capabilities.
Demonstrates how to use named parameters
 
"""

MEI_Type= [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]
Read_Dev_Id_code=[ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]
Object_Id= [ 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 59, 60, 61, 62, 63, 64, 65, 66, 67, 68, 69, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 251, 252, 253, 254, 255]
 
#MEI_Type= range(0,256)
#Read_Dev_Id_code=range(0,256)
#Object_Id=range(0,256)


print "Test case Initializing quantity: %d" % len(MEI_Type)
print "Test case Initializing byte_count: %d" % len(Read_Dev_Id_code)
print "Test case Initializing num_values: %d" % len(Object_Id)

parameters = [ ( "MEI_Type"
               ,MEI_Type  )
             , ( "Read_Dev_Id_code"
               , Read_Dev_Id_code)
             ############################
             , ( "Object_Id"
               ,Object_Id )
             
             ]

def is_valid_combination( values, names ):

    dictionary = dict( zip( names, values ) )
    #print dictionary 
    """
    Should return True if combination is valid and False otherwise.
    
    Dictionary that is passed here can be incomplete.
    To prevent search for unnecessary items filtering function
    is executed with found subset of data to validate it.
    """

    rules = [
            lambda d: 1 == d["Read_Dev_Id_code"] and d[0<="Object_Id"<3]  
           ,lambda d: 2 == d["Read_Dev_Id_code"] and d[3<="Object_Id"<129]
           ,lambda d: 3 == d["Read_Dev_Id_code"] and d[128<"Object_Id"<256]
            ]
    
    for rule in rules:
        try:
            if rule(dictionary):
                return False
        except KeyError: pass
    
    return True
                  
pairwise = all_pairs(
      [ x[1] for x in parameters ]
    , filter_func = lambda values: is_valid_combination( values, [ x[0] for x in parameters ] )
    )
p=list(all_pairs(
        [x[1] for x in parameters],
        filter_func=lambda values: is_valid_combination(
            values, [x[0] for x in parameters])))


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




    #object 
#for i, v in enumerate(pairwise):
#    print "%i:\t%s" % (i, str(v))
#print pairwise
print("PAIRWISE:list")
#print p
print len(p)
#or i, pairs in enumerate(pairwise):
#    print("{:2d}: {}".format(i, pairs))

#for key in sorted(dictionary.iterkeys()):
#    print "%s: %s" % (key, dictionary[key])
#sorted(dictionary.items(), key=lambda x: x[1])

        