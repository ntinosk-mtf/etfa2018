#!/usr/bin/env python3

"""
Demo of the basic functionality - just getting pairwise combinations
and skipping previously tested pairs.
"""

from allpairspy import AllPairs


parameters = [
    ["Brand X", "Brand Y"],
    ["98", "NT", "2000", "XP"],
    ["Internal", "Modem"],
    ["Salaried", "Hourly", "Part-Time", "Contr."],
    [6, 10, 15, 30, 60],
]
# sample parameters are is taken from
# http://www.stsc.hill.af.mil/consulting/sw_testing/improvement/cst.html

tested = [
    ["Brand X", "98", "Modem", "Hourly", 10],
    ["Brand X", "98", "Modem", "Hourly", 15],
    ["Brand Y", "NT", "Internal", "Part-Time", 10],
]

print("PAIRWISE:")
for i, pairs in enumerate(AllPairs(parameters, previously_tested=tested)):
    print("{:2d}: {}".format(i, pairs))
