
#def hex_to_binary(hex_number: str, num_digits: int = 8) -> str:



def int_to_binary_string(number, bit_width):
    """
    Convert a number to a binary string.

    @type  number:    int
    @param number:    (Optional, def=self._value) Number to convert
    @type  bit_width: int
    @param bit_width: (Optional, def=self.width) Width of bit string

    @rtype:  str
    @return: Bit string
    """
    return "".join(map(lambda x: str((number >> x) & 1), range(bit_width - 1, -1, -1)))


print(int_to_binary_string (250, 16))
