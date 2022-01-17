# MTF-Storm: a high performance fuzzer for Modbus/TCP
MTF-Storm is a highly effective fuzzer for industrial systems employing Modbus/TCP connectivity. It achieves high fault coverage, while offering high performance and quick testing of the System-Under-Test (SUT). Analogously to its predecessor MTF, MTF-Storm operates in 3 phases: a) reconnaissance b) fuzz testing and failure detection. Reconnaissance identifies the memory organization of the SUT and the supported functionality, enabling selection and synthesis of fuzz testing sequences that are effective for the specific SUT. MTF-Storm develops its test sequences systematically, starting  with single field tests and proceeding with combined field tests, adopting techniques for automated combinatorial software testing and reducing the test space through partitioning field value ranges. MTF-Storm has been used to evaluate 9 different Modbus/TCP implementations and has identified issues with all of them, ranging from out-of-spec responses to successful denial-of-service attacks and crashes.

![This is an image](https://github.com/ntinosk-mtf/etfa2018/blob/main/MTF_Storm/png/run_MTF-Storm.png)
MTF-Storm[2] extends MTF [1] (cf https://github.com/artemiosv/etfa2015) introducing novel techniques and methods in the selection of values and the format alteration techniques. MTF-Storm adopts a systematic approach to exercise values of packet fields and format changes, in contrast to the random values and changes used by MTF. 
# Source code
Source code for Modbus/TCP fuzzer (MTF-Storm) used for ETFA 2018 paper [2]
 # Features
*  Informed fuzzer operating in three phases
*  Match reconnaissance findings and SUT capabilities.  Systematic  approach to values: (i) invalid values(ii) “interesting” values  (iii) “non-interesting” values 
* Packet format alterations (Two or more ADU per TCP segment, appending sequences of  “interesting”, “non-interesting” bytes to PDUs) 
*  Support fuzzing  every FC in spec (TCP and Serial)
*  Failure detection, log files (error and info), automatic evaluation

# Installation and runing
See in file mtf_storm_instructions-en.txt  (current version use python 2.7.3)

# Soon ...
* New version for python 3.x 
* Many changes and improvements

# See  work:
[1] A.G. Voyiatzis, K. Katsigiannis and S. Koubias, “A Modbus/TCP Fuzzer for testing internetworked industrial systems.” In Proceedings of the 20th IEEE International Conference on Emerging Technologies and Factory Automation (ETFA), Luxembourg, Sept. 8-11, 2015, pp. 1-6.

[2] Katsigiannis K, and Dimitrios Serpanos. "MTF-Storm: a high performance fuzzer for Modbus/TCP."  2018 IEEE 23rd International Conference on Emerging Technologies and Factory Automation (ETFA). Vol. 1. IEEE, 2018.

[3] Serpanos, Dimitrios, and Konstantinos Katsigiannis. "Fuzzing: Cyberphysical System Testing for Security and Dependability."  Computer 54.9 (2021): 86-89.

Code compiled by K. Katsigiannis. For related questions please contact kkatsigiannis@upatras.gr or katsigiannis.kon@gmail.com

