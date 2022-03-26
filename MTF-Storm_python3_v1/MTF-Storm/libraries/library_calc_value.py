#!/usr/bin/env python
# -*- coding: utf-8 -*-

from  libraries.s_primitives import *
import fuzz_session

#---------------------------------------------------------------------------------------------------------
# library for static fuzz VALUE 
# The class  implements integer fuzz heuristics  library of static fuzz VALUE
# Add the supplied integer and border cases to the integer fuzz heuristics library
# negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
# lib_word_binary.extend(bit_field(0, 16, 255, "<","ascii", True).fuzz_library)                       
# lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library      
# lib_dword_binary.extend(bit_field(214748364, 32, 2147483648, "<","ascii", True).fuzz_library)
   
# self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
# only smart values  bound +-1
# self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
# self.library only smart values  bound +-5
    
# add the library num rang 1000 and bound (+-20) 
# for i in range(0, self.max_num,1000):
#     self.add_integer_bound(i,self.library)
        
# build the fuzz library num rang 1000 not  bound (+-20)
#    for i in range(0, self.max_num,1000):
#      self.library.append(i)
#self.interesting_strings=
#---------------------------------------------------------------------------------------------------------
class list_of_fuzz(object):
    '''
    library for static fuzz VALUE 
    '''
    def __init__ (self,max_num=None,library=None):
        self.interesting_hex=[];self.max_num = 65535
        self.illegal_pdu_len=[];self.bound=[]
        if library is None:self.library = []            
        self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library   
        self.lib_word_binary=bit_field(0, 16, -32768, "<","ascii", signed=True,fuzzable=True).fuzz_library
        self.simple_lib_word_binary=bit_field_simple(0, 16, 65535, "<","ascii", signed=True,fuzzable=True).fuzz_library
        self.lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library
        #for all list min//max address
        self.MIN_COILS=fuzz_session.MIN_COILS;self.MAX_COILS=fuzz_session.MAX_COILS
        self.MIN_IN_REG=fuzz_session.MIN_IN_REG;self.MAX_IN_REG=fuzz_session.MAX_IN_REG   
        self.MIN_DIS_IN=fuzz_session.MIN_DIS_IN;self.MAX_DIS_IN=fuzz_session.MAX_DIS_IN       
        self.MIN_HO_REG=fuzz_session.MIN_HO_REG;self.MAX_HO_REG=fuzz_session.MAX_HO_REG
       
        self.address_list_bound_COILS=[self.MIN_COILS,self.MAX_COILS]
        self.address_list_bound_DIS_IN=[self.MIN_DIS_IN,self.MAX_DIS_IN]
        self.address_list_bound_IN_REG=[self.MIN_IN_REG,self.MAX_IN_REG]
        self.address_list_bound_HO_REG=[self.MIN_HO_REG,self.MAX_HO_REG]
        self.iterest_value=[0,128, 255, 256, 257, 259,260,261, 263,511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8196, 10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1,0xFFFF]

        self.common_len_valid=[1, 2, 3, 4, 5,  8,  16,  32, 63, 64, 65, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 245, 247, 249, 250]               

    def add_integer_bound(self, integer,library,b):
        '''
        Add the supplied integer and border cases to the integer fuzz heuristics library.
        @type  integer: Int
        @param integer: Integer to append to fuzz heuristics
        '''

        for i in range(-b, +b):
            case = integer + i
            # ensure the border case falls within the valid range for this field.
            if (0<= case <= self.max_num and self.max_num >0 ) :
                if case not in library:
                    library.append(case)
            elif  (self.max_num <= case <= -self.max_num) :                   
                if case not in library:
                    library(case)          
                 

    def num_of_list (self):
        '''
        Calculate and return the total number of list.
        @rtype:  Integer
        @return: Number of mutated forms this primitive can take
        '''
        return len(self.library)    


    def illegal_len_list(self):
        '''
        fuzz heuristics for test not specified len ADU or PDU
        add extra item in list,  e.g tcp frame 1500 +-  ,
        range(243,253,2)) as ADU 243+12 ,(255,265 ) (e.g len FC01 =12B)
        remove all empty strings //dumple item// sort
        list(filter(lambda x: x!= 0 and  x<=255, self.library)), valid len
        list(filter(lambda x: x!= 0 and  x>=255, self.library)), valid len
        self.common_len_valid=[1, 2, 3, 4, 5,  8,  16,  32, 63, 
        64, 65, 123, 124, 125, 126, 127, 128, 129, 130, 131, 132, 133, 243, 245, 247, 249, 251, 252, 253, 254, 255]
        The maximum amount of data TCP can hold is 1460 Bytes, self.library.extend(list(range(1440,1480,2)))

        '''
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library.extend(list(range(1440,1480,2)));self.library.extend(list(range(243,253,2))) #data TCP can hold is 1460 Bytes.  
        self.library=list([x for x in self.library if x<=33000])
        self.library.extend([5000, 10000, 20000, 0xFFFF-2, 0xFFFF-1,0xFFFF])
        self.library=list(set(self.library)) ;   self.library.sort(reverse=False)                    
        return list([x for x in self.library if x!= 0 and  x>=250])+self.common_len_valid

    #  --NOT USE                               
    def list_pdu_len(self) :
        pdu_len=self.illegal_len_list()                      
        fuzz_session.len_of_list=len(pdu_len)
        return pdu_len
    
     #-- NOT USE 
    def init_illegal_pdu_list(self):                
        self.illegal_pdu_len=self.illegal_len_list()   
        fuzz_session.illegal_pdu_len= self.illegal_pdu_len
        fuzz_session.len_of_list=len(self.illegal_pdu_len)
        return

    def list_of_address(self,MIN,MAX) :
        """
        add extra item in fuzz library for  min//max address,
        remove all empty strings and dumple item and sort
        build the fuzz library for min//max address bound +-20 (,
        Bitwise-AND, signed 16-bit numbers as -256 ,-512 ,-1024
        self.library common smart value +-5, and value > max  %1000 +-2 
        
        """
        final_list_address=[]; list_address=[];self.bound=[MIN,MAX,MAX//2,MAX//3]
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library        
        for x in self.bound:  
              self.add_integer_bound(x,list_address,22)
        for i in range(0, MAX,1000):
             self.add_integer_bound(i,list_address,5)
        for x in list([x for x in range(MAX,65535) if x % 1000==0]):  
              self.add_integer_bound(x,list_address,2) 
        for x in list([x for x in range(0,MIN) if x % 1000==0]):  
              self.add_integer_bound(x,list_address,2)            
          
        #Bitwise-AND, unsigned 16-bit numbers                                     
        self.lib_word_binary=[x & 0xFFFF for x in self.lib_word_binary]                      
        final_list_address= list_address+self.library+list (set(self.lib_word_binary))
        final_list_address=list(set(final_list_address)); final_list_address.sort(reverse=False)                                      
        return final_list_address
        
    def list_address_for_cart_prod(self,MIN,MAX,b) :
        """
        limited number of interests, use fuzzing parameter PDU
        add item in fuzz library for  min//max address,
        build the fuzz library for min//max address,
        Bitwise-AND, "smart" values signed 16-bit numbers as -256 ,-512 ,-1024, ..-16384 and  boundary to self.max_num-16384//48k ram 
        build the fuzz library not boundary,remove all empty strings and dumple item and sort
        if <5 use self.library_simple

        """                   
        final_list_address=[];list_address=[]; self.bound=[MIN,MAX]
        for x in self.bound:  
              self.add_integer_bound(x,list_address,b) 
        if b<5:
            final_list_address=self.library_simple+list_address+[5000,10000,49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535]   
        else:
            if MAX>32768:self.library=list([x for x in bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library if x<=(49152+5)])            
            else :self.library=list([x for x in bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library if x<=(32768+5)])
            final_list_address=self.library+list_address+[5000,10000,49152, 57344, 61440, 63488, 64512, 65024, 65280, 65408, 65472, 65504, 65530, 65531, 65532, 65533, 65534, 65535]    
                                            
        final_list_address=list(set(final_list_address));final_list_address.sort(reverse=False) 
        return final_list_address   

    def list_of_quantity(self,MIN,MAX) :
        """
        add extra item in fuzz library for quauntity
        remove all empty strings //and dumple item//sort
        build the fuzz library for quauantity (min//max ),
        Bitwise-AND, signed 16-bit numbers -256 ,-512 ,-1024
        bound for quauantity register and coil, 
        self.library common smart value +-5, and value > max  %1000 +-2 
        """
        
        list_qua=[];self.bound=[MIN,MAX,MAX//2, MAX//3] ; self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        for i in range(0, MAX,1000):
             self.add_integer_bound(i,list_qua,5)

        for x in list([x for x in range(MAX,65535) if x % 1000==0]):  
              self.add_integer_bound(x,list_qua,2)             
        
        for x in self.bound:  
              self.add_integer_bound(x,list_qua,22) 
                                              
        self.lib_word_binary=[x & 0xFFFF for x in self.lib_word_binary]
        final_list_qua =self.library+list(self.lib_word_binary)+list_qua
        final_list_qua=list(set(final_list_qua));final_list_qua.sort(reverse=False) 
        return final_list_qua
        
    def list_quantity_for_cart_prod(self,MIN,MAX,b) :
        """
        limited number of interests,  use fuzzing parameter PDU
        add item in fuzz library for quauntity
        build the fuzz library for quauantity (min//max ),
        Bitwise-AND, signed 16-bit numbers -256 ,-512 ,-1024, -16384 , not boundary [5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        bound for quauantity register and coil,
        remove all empty strings //and dumple item//sort
        if b (bountery) <5 use self.library_simple
        """
        final_list_qua=[];list_qua=[];self.bound=[MIN,MAX]    
        for x in self.bound:  
              self.add_integer_bound(x,list_qua,b)

        if b<5:
            self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library
            final_list_qua =list_qua+self.library_simple+[5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        else :
             self.library=list([x for x in bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library if x<=(32768+5)])
             final_list_qua =list_qua+self.library+[5000,10000,20000,65530, 65531, 65532, 65533, 65534, 65535]
        
        final_list_qua=list(set(final_list_qua));final_list_qua.sort(reverse=False)
        return final_list_qua 
    
    def lib_word32(self):   
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
        e.g 32-bit only sin negative
        self.lib_word_binary=bit_field(0, 16, -32768, "<","ascii", signed=True,fuzzable=True).fuzz_library
        def add_integer_bound(self, integer,library,b):
        lib_word_binary.extend(bit_field(0, 16, 255, "<","ascii", True).fuzz_library)                       
        lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library      
        lib_dword_binary.extend(bit_field(214748364, 32, 2147483648, "<","ascii", True).fuzz_library) 
        test  library  (word32): 288 test
        """ 
        list_of_boun=[];self.lib_word_binary=bit_field(0, 32, -32768, "<","ascii", True).fuzz_library
        #self.lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library
             
        for x in self.lib_word_binary:  
              self.add_integer_bound(x,list_of_boun,10)            
        
        final_lib_word32=self.lib_word_binary+list_of_boun + self.lib_dword_binary
        final_lib_word32=list(set(final_lib_word32));final_lib_word32.sort(reverse=False) 
        return list([x for x in final_lib_word32 if x<= 0]) 
    
    def lib_word(self):   
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
        e.g 16bit /
        lib_word_binary.extend(bit_field(0, 16, 255, "<","ascii", True).fuzz_library)                       
        lib_dword_binary=bit_field(0, 32, -2147483648, "<","ascii", True).fuzz_library      
        lib_dword_binary.extend(bit_field(214748364, 32, 2147483648, "<","ascii", True).fuzz_library) 
        test  library  (word16)=1629,  if not remove sin test=1825
        """ 
        list_of_boun=[];self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        
        for i in range(0, self.max_num,1000):
             self.add_integer_bound(i,list_of_boun,5)
             
        for x in self.library:  
              self.add_integer_bound(x,list_of_boun,10)            
        
        self.lib_word_binary=[x & 0xFFFF for x in self.lib_word_binary]      #(remove sin)
        final_list=self.library+list(self.lib_word_binary)+list_of_boun
        final_list=list(set(final_list));final_list.sort(reverse=False) 
        return  final_list
    
    def lib_word_cart(self):                   
        """
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library.The bit field a number of variable length word,dword, qword 
        use for cartesian protect
        not bound value  for boundaries simple +-1
        final_list =[0, 1, 2, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65, 127, 128, 129, 255, 256, 257, 511, 512, 513, 1023, ..
        65472, 65473, 65503, 65504, 65505, 65519, 65520, 65521, 65527, 65528, 65529, 65531, 65532, 65533, 65534, 65535]
        test library: 59 value
        """ 
        list_of_boun=[];self.library_simple=bit_field_simple(0, 16, 65535 , "<","ascii", True).fuzz_library 
        self.lib_word_binary=[x & 0xFFFF for x in self.lib_word_binary]      
        final_list=self.library_simple
        final_list=list(set(final_list))
        final_list.sort(reverse=False)   
        return  final_list

    def lib_byte_test(self,MIN=0,SPEC=0,MAX=65535):   #add  new 18.03.20//and 29.11.20
        """
        limited number, library for 1 byte fields and value use the 2-way test, MIN,MAX, SPECIAL VALUE, +-20 
        Add the supplied integer and border cases to the integer fuzz heuristics library
        negatve integer build  fuzz library use for 1 byte or 2 byte fields  test  2-way
        for 1 byte fields  single test add MAX//3,MAX//5, and special value +-10
        self.library=60 value
        return sort

        """
        tmp=[]; end=[];list_of_boun=[];self.bound=[MIN,SPEC,MAX,MAX//3,MAX//5] 
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        if MAX==256 :
            for x in self.bound:  
              self.add_integer_bound(x,tmp,8)
            end=tmp+self.library
                       
        else:    
            for x in self.bound:  
                  self.add_integer_bound(x,tmp,22)
            for x in self.library:  
                  self.add_integer_bound(x,list_of_boun,22)
            end=tmp+self.simple_lib_word_binary+list_of_boun              
       
        end=list(set(end));end.sort()
        if MAX==65535 :
            return list([x for x in end if x<= 65535])
        return list([x for x in end if x<= 255])
        
    def lib_exhaustive_256(self):
        """
        integer exhaustive fuzz heuristics library (all value), not sort 
        negatve integer build  fuzz library. use for byte_count field in test_field_PDU and unit_id in MBAP
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        list(filter(lambda x:x not in self.library,list(range(0, 256)))), value not interesting and valid
        sort 0,6 only interesting first and other valid next 

        """ 
        return list([x for x in self.library+list([x for x in list(range(0, 256)) if x not in self.library]) if x<= 255])

    def lib_exhaustive_65535(self):
        """
        integer exhaustive fuzz heuristics library
        negatve integer build  fuzz library. use for exhaustive fields 2 BYTE  

        """ 
        return list(range(0, 65536))

    def lib_interesting_256(self):
        """
        integer interesting value up to 256  heuristics library
        negatve integer build  fuzz library. use for byte_count, dumplecate ADU,
        field in test_field_PDU and unit_id in MBAP
        case=59  

        """        
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library=list(set(self.library));self.library.sort(reverse=False)               
        return list([x for x in self.library if 0<x<= 255])       

    def lib_interesting_256_exte(self):
        """
        integer interesting value up to 256  and extend 512,1024,2048,4096 heuristics library
        negatve integer build  fuzz library Multiple ADU,
          
        """        
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library=list(set(self.library));self.library.sort(reverse=False)      
        return list([x for x in self.library if x<= 256]) +[512,1024,2048,4096]
        

    def lib_interesting_128_to_255(self):
        """
        integer interesting value  128_to_255 heuristics library
        negatve integer build  fuzz library. use to check FC Exception
        boundary User-defined, public_codes, user_codes [171,191,201,226,227,237,238]

        """
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        self.library.extend(list(range(128,150,1)));self.library=list(set(self.library)) 
        self.library.sort(reverse=False)
        return list([x for x in self.library if 128<= x<= 255]) + [171,191,201,226,227,237,238]

    def lib_of_MBAP_length(self) :
        """
        iterest_value=[0,128, 255, 256, 257, 259,260,261, 263,511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8196,10000, 20000,
                       32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1,65535]
        list fuzz library for test MBAP length..-to be configured !!not sort with dumplicate MBAP_length.extend(list(range(0,10,1))
        repait bount (260),repait space (0,9)
        remove all empty strings, not sort with dumplicate 
        [666] flag to stop test as last elements
        case=
        len           4        1368        
        """
        final_list_length=[]
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        MBAP_length=list(range(1450,1550,1)) ;  MBAP_length.extend(list(range(250,270,1)));MBAP_length.extend(list(range(0,10,1))) 
        
        for i in range(0, self.max_num,1000):
             self.add_integer_bound(i,MBAP_length,3)
        MBAP_length.extend(list(range(250,270,1))) ;MBAP_length.extend(list(range(0,10,1))); MBAP_length.extend(list(range(2054,32768,64)))
        MBAP_length.extend(list(range(0,10,1))) ;final_list_length.extend(self.library)          
        final_list_length = list(set(self.library))+self.iterest_value+MBAP_length+self.iterest_value+[666]       
        return list([x for x in final_list_length if x<65536])  

    def lib_of_MBAP_transid(self,MIN,MAX) :
        """
        self.iterest_value=[0,128, 255, 256, 257, 259,260,261, 263,511, 512, 513, 1023, 1024, 2048, 2049, 4095, 4096, 4097, 5000, 8196,10000, 20000,
                      32762, 32763, 32764, 32765, 32766, 32767, 32768, 32769, 0xFFFF-2, 0xFFFF-1,65535]
        list fuzz library for test trans id, step , reversed ,....
        case=9437(with dumplicate)
        
        """
        MBAP_same_value=[];MBAP_inc_value=[];MBAP_transid=list(range(0,99))
        MBAP_iterest_value_rev=list(reversed(self.iterest_value))
        # build the fuzz library for (min//max)
        MBAP_inc_value=list(range(MIN,MAX,16)) ;  MBAP_inc_value.extend(list(range(MIN,MAX,128)))    
        MBAP_inc_value.extend(list(range(MIN,MAX,2048)));MBAP_rev_value=list(reversed(MBAP_inc_value))    
        return self.iterest_value+MBAP_iterest_value_rev+MBAP_transid+MBAP_inc_value+MBAP_rev_value

    def lib_of_MBAP_protocol(self,MIN,MAX) :
        """
        add extra item in list fuzz library for test MBAP protocol(
        remove all empty strings and dumple item//sort,and valid value
        final_list_prot=list(set(final_list_prot)) ,remove dumplicate
        total of test  MBAP protocol: 942
        """
        final_list_prot=[]; MBAP_protocol=[]
        self.bound=[MIN,MAX];self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        
        # build the fuzz library for (min//max)
        for x in self.bound:  
              self.add_integer_bound(x,MBAP_protocol,20)
        for i in range(0, self.max_num,1000):
             self.add_integer_bound(i,MBAP_protocol,5)
        final_list_prot= self.library+MBAP_protocol
        final_list_prot=list(set(final_list_prot))          
        final_list_prot.sort(reverse=False)
        return list([x for x in final_list_prot if x<65536])                                                       

    def lib_test_sub_diag(self):
        """
        add extra item in list self.library, remove all empty strings //dumple item// sort
        """
        self.library=bit_field(0, 16, 65535 , "<","ascii", True).fuzz_library
        diagnostics_library=self.library+list(range(0,21,1)) ;diagnostics_library=list(set(diagnostics_library))                                     
        diagnostics_library.sort(reverse=False)
        return diagnostics_library
        