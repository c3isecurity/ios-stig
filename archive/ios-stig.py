#ios-stig.pl
from sys import argv
from ciscoconfparse import *

#argv variables. input_file is the config file to parse
script, input_file = argv
print "IOS-STIG Python STIG checker."
print "C3isecurity Copy Right 2011."
print "version 0.01\n"

print "Starting IOS STIG check"
#parse = CiscoConfParse("sample_01.ios")
parse = CiscoConfParse (input_file)
print "opening %r" % input_file

#NET0949 CEF check. Look for "ip cef"
NET0949 = parse.find_lines("ip cef",exactmatch=True)

print "Findings NET0949 %r" % NET0949 
print "End of IOS STIG check"
