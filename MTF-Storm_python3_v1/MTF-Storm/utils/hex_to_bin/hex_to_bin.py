
#def hex_to_binary(hex_number: str, num_digits: int = 8) -> str:
def hex_to_binary(number: 1, num_digits: int = 16) -> str:
    """
    Converts a hexadecimal value into a string representation
    of the corresponding binary value
    Args:
        hex_number: str hexadecimal value
        num_digits: integer value for length of binary value.
                    defaults to 8
    Returns:
        string representation of a binary number 0-padded
        to a minimum length of <num_digits>
    """
    #return str(bin(int(hex_number, 16)))[2:].zfill(num_digits)
    return (bin(number))[2:].zfill(num_digits)
  
#tuble
a=hex_to_binary (10), 16
print(hex_to_binary (10), 8)
print((hex_to_binary (10), 16)[0])
print (a)