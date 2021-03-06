
#!/usr/bin/env python
# -*- coding: utf_8 -*-
"""
This is distributed under GNU LGPL license, 
Source code for Modbus/TCP fuzzer used for the ETFA 2015
Code compiled by K. Katsigiannis.
For related questions please contact kkatsigiannis@upatras.gr 

"""

#-------------------------------------------------------------------------------
#HexByteConversion
#Convert a byte string to it's hex representation for output or visa versa.
#ByteToHex converts byte string "\xFF\xFE\x00\x01" to the string "FF FE 00 01"
#HexToByte converts string "FF FE 00 01" to the byte string "\xFF\xFE\x00\x01"
# test data - different formats but equivalent data
#__hexStr1  = "FFFFFF5F8121070C0000FFFFFFFF5F8129010B"
#__hexStr2  = "FF FF FF 5F 81 21 07 0C 00 00 FF FF FF FF 5F 81 29 01 0B"
#__byteStr = "\xFF\xFF\xFF\x5F\x81\x21\x07\x0C\x00\x00\xFF\xFF\xFF\xFF\x5F\x81\x29\x01\x0B"

#-------------------------------------------------------------------------------
def ByteToHex( byteStr ):
    """
    Convert a byte string to it's hex string representation e.g. for output.
    """
    
    # Uses list comprehension which is a fractionally faster implementation than
    # the alternative, more readable, implementation below
    #   
    #    hex = []
    #    for aChar in byteStr:
    #        hex.append( "%02X " % ord( aChar ) )
    #
    #    return ''.join( hex ).strip()        

    return ''.join( [ "%02X " % ord( x ) for x in byteStr ] ).strip()
    #return ' '.join( [ "%02X" % ord( x ) for x in byteStr ] )                                #not space

#-------------------------------------------------------------------------------

def HexToByte( hexStr ):
    """
    Convert a string hex byte values into a byte string. The Hex Byte values may
    or may not be space separated.
    """
    # The list comprehension implementation is fractionally slower in this case    
    #
    #    hexStr = ''.join( hexStr.split(" ") )
    #    return ''.join( ["%c" % chr( int ( hexStr[i:i+2],16 ) ) \
    #                                   for i in range(0, len( hexStr ), 2) ] )
 
    bytes = []

    hexStr = ''.join( hexStr.split(" ") )

    for i in range(0, len(hexStr), 2):
        bytes.append( chr( int (hexStr[i:i+2], 16 ) ) )

    return ''.join( bytes )







#------------------------------------------------------------
# The functions below fuzz fields-not use
#------------------------------------------------------------
def rand_XShortField():                        # rundom hex 2 bytes
  # return hex(random.randint(0,65535))  
    start = datetime.now()     
                   
    random.seed(start)
    return random.randint(0,65535)


def rand_XByteField():                        # rundom hex 1 byte
   #return hex(random.randint(0,255))
   start = datetime.now()     
                   
   random.seed(start)
   return random.randint(0,255)

def rand_ByteEnumField():
   return random.randint(0,100)


def rand_FieldLenField():
   if random.randint(0,1) == 0:
      return 0
   else:
      return random.randint(1,5000)


def rand_ByteField():
   return os.urandom(random.randint(0,256))


def rand_IntEnumField():
   return random.randint(0,256)


def rand_StrLenField(data):
   bit = random.randint(0,3)
   if bit == 0:
      index = random.randint(0,len(data)-2)
      data = data[:index] + os.urandom(1) + data[index+1:]
   elif bit == 1:
      index = random.randint(0,len(data)-2)
      data = data[:index] + '\x00' + data[index+1:]
   elif bit == 2:
      data = data + os.urandom(random.randint(0,1000))
   elif bit == 3:
      data = '\x00'
   else:
      log('Error')
   return data

def rand_ShortEnumField():
   return random.randint(0,100)


#convert string to hex
def toHex(s):
    lst = []
    for ch in s:
        hv = hex(ord(ch)).replace('0x', '')
        if len(hv) == 1:
            hv = '0'+hv
        lst.append(hv)
    return reduce(lambda x,y:x+y, lst)

'''Generate random numbers using the time difference between loop
  iterations.  Quo is 'time' in Latin.'''
           
class Quo:
   
      def __init__(self):
        # Start time for later comparison
        self.start = datetime.now()
     
        # Sleep for a moment to allow `start` - `end` times to not be 0
        sleep(0.01)
     
      def get_raw_bytes(self, _len):
        '''Get raw random bytes, i.e., random bytes prior to hashing.'''
     
        _bytes = []
     
        for i in range(_len):
          byte = []
     
          for i in range(8):
            end = datetime.now()
            bit = int(str((self.start - end).total_seconds())[-1]) % 2
            byte.append(str(bit))
     
          _bytes.append(chr(int(''.join(byte), 2)))
        
        return ''.join(_bytes)
     
      def get_random_bytes(self, _len):
        '''Get truly random bytes, i.e., random bytes post hashing.'''
     
        random_bytes = []
     
        # sha256 wants a minimum input length of 32 bytes.  Since users
        # can request any byte length, round requests up to the nearest
        # 32 byte chunks.
        for i in range(int(ceil(_len / 32.0))):
          raw_bytes = self.get_raw_bytes(32)
     
          random_bytes.append(sha256(raw_bytes).digest())
     
        return ''.join(random_bytes)[:_len]
     
#----------------------------------------------------------------------------------#
#This class implements  BFS or DFS -not use yet
#----------------------------------------------------------------------------------#
class search():
    '''
    The class implements  breadth-first search (BFS) OR Depth-first search (DFS) traversal from a given graph 
     
    '''   
    def __init__(self):            
        #parents = {'N1': ['N2', 'N3', 'N4'], 'N3': ['N6', 'N7'], 'N4': ['N3'], 'N5': ['N4', 'N8'], 'N6': ['N13'],
        #           'N8': ['N9'], 'N9': ['N11'], 'N10': ['N7', 'N9'], 'N11': ['N14'], 'N12': ['N5']}
        parents = dict()
    
        parents = {
        0: [256, 512, 1024, 2048],
        252: [251],
        253: [252],
        254: [253],
        255: [254],
        256: [257, 255],
        257: [258],
        258: [259],
        259: [260],
        260: [261],
        508: [507],
        509: [508],
        510: [509],
        511: [510],
        512: [513, 511],
        513: [514],
        514: [515],
        515: [516],
        516: [517],
        }   

    def DFS_dist_from_node(query_node, parents):
        """Depth-first search: not useReturn dictionary containing distances of parent GO nodes from the query"""
        result = {}
        stack = []
        stack.append( (query_node, 0) )
        while len(stack) > 0:
            #print("stack=", int(stack[0][0]))            # check node
            print("stack=", stack)                        #original           
            node, dist = stack.pop()
            result[node] = dist
            if node in parents: 
                for parent in parents[node]:
                    # Get the first member of each tuple, see 
                    # http://stackoverflow.com/questions/12142133/how-to-get-first-element-in-a-list-of-tuples
                    stack_members = [x[0] for x in stack]
                    if parent not in stack_members:
                        stack.append( (parent, dist+1) )
        return result    

    #
    def BFS_dist_from_node(query_node, parents):
        """ breadth-first search :    not use, Return dictionary containing minimum distances of parent GO nodes from the query"""
        result = {}
        queue = []
        queue.append( (query_node, 0) )
        while queue:       
            print("queue=", int(queue[0][0]))              #a node check
            node, dist = queue.pop(0)
            result[node] = dist
            if node in parents:                           # If the node *has* parents
                for parent in parents[node]:
                    # Get the first member of each tuple, see 
                    # http://stackoverflow.com/questions/12142133/how-to-get-first-element-in-a-list-of-tuples
                    queue_members = [x[0] for x in queue]
                    if parent not in result and parent not in queue_members: # Don't visit a second time
                        queue.append( (parent, dist+1) )
                    return result    


