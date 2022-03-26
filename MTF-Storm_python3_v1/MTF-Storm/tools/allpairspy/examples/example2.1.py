#!/usr/bin/env python3

"""
Demo of filtering capabilities
"""

from allpairspy import AllPairs


def is_valid_combination(row):
    """
    This is a filtering function. Filtering functions should return True
    if combination is valid and False otherwise.

    Test row that is passed here can be incomplete.
    To prevent search for unnecessary items filtering function
    is executed with found subset of data to validate it.
    """

    n = len(row)

    if n > 1:
        # Brand Y does not support Windows 98
        if "98" == row[1] and "Brand Y" == row[0]:
            return False

        # Brand X does not work with XP
        if "XP" == row[1] and "Brand X" == row[0]:
            return False

    if n > 4:
        # Contractors are billed in 30 min increments
        if "Contr." == row[3] and row[4] < 30:
            return False

    return True


# sample parameters are is taken from
# http://www.stsc.hill.af.mil/consulting/sw_testing/improvement/cst.html
parameters = [
    ["Brand X", "Brand Y"],
    ["98", "NT", "2000", "XP"],
    ["Internal", "Modem"],
    ["Salaried", "Hourly", "Part-Time", "Contr."],
    [6, 10, 15, 30, 60],
]

print("PAIRWISE:")
for i, pairs in enumerate(AllPairs(parameters, filter_func=is_valid_combination)):
    print("{:2d}: {}".format(i, pairs))
