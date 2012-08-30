#ios-stig.py

#This python program attempt to run a STIG scan aginst ag Cisco IOS config
#file.  This grew from learning python programing and getting a detailed
#understanding of the of the DISA Network Infrastructure STIG. 
#If you don't understand what a STIGs is look at http://wwww.c3isecurity.com
#There are many other commercial and opensource tools that can check for
#and parse the Cisco IOS device.  This is just another experimental 
#learning platform.  Don't use this for offical audits.  If you do double/triple check for validation.

#----DEPENDANCIES!!!!!!!!!!!!!!!!------------
# the ciscoconfparse!!!!!!!!!!!!!
# I am leveraging the great work he has done!  


# Basic construct of the program
# Profile:
#   Infrastructure Router
#     
#   Type:
#       Checks:

#Require config file for input
#
#List STIG NETXXXX checks < The strings listed on the NETXXXX are 
#my candidates for being in the Cisco IOS CCE.   


#IMPORT section
from sys import argv
from ciscoconfparse import *

#AT somepoint I'll include exteral input files for the NETXXXX IDs.
#argv variables. input_file is the config file to parse
script, input_file = argv
print "\nIOS-STIG Python STIG checker."
print "Copyright (c) 2012, C3isecurity."
print "All rights reserved."
print "version 0.04\n"

print "Starting IOS STIG check"
parse = CiscoConfParse (input_file)
print "opening %r\n" % input_file

#Sting Section used to validate Benchmarks and CCE
#Common Configuration Enumeration (CCE)
#Below are the strings used to parse for checks.  The NET_ IDs are for
#reference to STIG checks.

# IPv6 section
NET_IPV6_033 = "ipv6 cef"
NET_IPV6_015 = "ipv6 ospf authentication"
NET_IPV6_015a = "ipv6 ospf encryption ipsec"

# SSH section
NET_1636 = "transport input ssh"
NET_1647 = "ip ssh version 2"
NET_1646 = "ip ssh authentication-retries 3"
NET_1645 = "ip ssh time-out"

# VLAN section
NET_VLAN_004 = "no ip address"
NET_VLAN_004a = "shutdown"

# AAA section
NET0433 = "aaa new-model" 
NET0433a = "aaa authentication login"

# Services section
NET0600 = "service password-encryption"
NET0720 = "service tcp-small-servers"
NET0722 = "no service pad"
NET0724 = "service tcp-keepalives-in"
NET0726 = "ip identd"
NET0730 = "ip finger"
NET0740 = "ip http server"
NET0744 = "ip rcmd rcp-enable"
NET0744a = "ip rcmd rsh-enable"
NET0750 = "no ip bootp server"
NET0728 = "no service dhcp"
NET0760 = "no boot network"
NET0760a = "no service config"
NET0405 = "service call-home"
NET_0780 = "no ip proxy-arp"
NET_0949 = "ip cef"

# Interface section
NET0770 = "no ip source-route"
NET0780 = "no ip proxy-arp"
NET0790 = "no ip directed broadcast"
NET0800 = "no ip redirects"
NET0800a = "no ip unreachables"
NET0900 = "snmp-server trap-source Loopback"

NET0781 = "no ip gratuitous-arps"

NET0960 = "ip tcp intercept list"
NET0965 = "ip tcp synwait-time 10"

# loopback section
NET0897 = "ip tacacs source-interface Loopback"
NET0897a = "ip radius source-interface Loopback"
NET0898 = "logging source-interface Loopback"
NET0899 = "ntp source Loopback"
NET0901 = "ip flow-export source Loopback"

# Multicast section
NET_MCAST_010 = "ip pim sparse-mode"
NET_MCAST_010a = "ip multicast boundry"

NET0340 = "^banner login"
NET0340a = "^banner motd"
######### END string seciton ###########

# Variable to Totals at the end
# Passed counted as compliance 
Passed = 0
Failed = 0
NA = 0

# def to find_lines in the config. Good for finding simple configs.
# exmaple "ip ssh version 2".  Use exactmatch to match exactly.
def check(NET_ID, CCE_ID):
    NET_Check = parse.find_lines(CCE_ID ,exactmatch=True)
    if NET_Check == [CCE_ID]:
        print "PASS: %r" % NET_ID
        global Passed
        Passed += 1
    else:
        print "FAIL: %r " % NET_ID 
        global Failed
        Failed += 1

# def to check the precense of the command. if found its a failed.
def check_there(NET_ID, CCE_ID):
    NET_Check = parse.find_lines(CCE_ID ,exactmatch=True)
    if NET_Check == [CCE_ID]:
        print "FAIL: %r" % NET_ID
        global Passed
        Passed += 1
    else:
        print "PASS: %r " % NET_ID 
        global Failed
        Failed += 1

# def to check the banner settings
# for future enhancement we could use predefined text file?
def banner_check():
    NET_Check = parse.find_lines ("^banner")
    if NET_Check == "banner login":
        print "PASS Banner check: %r"
        global Passed
        Passed += 1
        print NET_Check
    elif NET_Check == "banner motd":
        print "Pass Banner check motd"
    else:
        print "FAIL: NET0304 Banner check" 
        global Failed
        Failed += 1

# def to check the line vtys
def check_line():
    line_vty = parse.find_parents_wo_child("^line vty",NET_1636)
    global Failed    
    Failed += 1
    print "Following Interfaces Failed NET1636:"
    for i in line_vty:
        print "\tFAIL: %r" % i

# def to check interfaces.
def check_interface_config(NET_ID, NET_ID1):
    int_config = parse.find_parents_wo_child("^interface",NET_ID1)
    global Failed    
    Failed += 1
    print "Following Interfaces Failed %r:" % NET_ID
    for i in int_config:
        print "\tFAIL: %r" % i
    int_config = parse.find_parents_w_child("^interface",NET_ID1)
    global Passed    
    Passed += 1
    print "Following Interfaces Passed %r:" % NET_ID
    for i in int_config:
        print "\tPASS: %r" % i

def test(NET_ID, CCE_ID):
    NET_Check = parse.find_lines(CCE_ID)
    if NET_Check and True:
        print "PASS: %r" % NET_ID
        global Passed
        Passed += 1
    else:
        print "FAIL: %r " % NET_ID 
        global Failed
        Failed += 1

# def to check for Multicast
def mcast_check():
    NET_MCAST = parse.find_lines ("^ip multicast-routing")
    if NET_MCAST and True:
        print "Multicast is enabled: "
        check_interface_config("NET-MCAST-010 pim settings", NET_MCAST_010)
        check_interface_config("NET-MCAST-010 Multicast boundry settings", NET_MCAST_010a)
       # global Passed
       # Passed += 1
    else:
        print "Multicast is not enable NA" 
        global NA
        NA += 1

# TYPE
# 
def NET_checks():
    print "---------------------------------------"
    print "NET Checks"
    check ("NET0949 CEF", NET_0949)
# SSH checks
    check ("NET1647 SSH version 2", NET_1647)
    check ("NET1646 SSH login attempt is set to 3", NET_1646)
    check ("NET1645 SSH time-out setting", NET_1645)
    check ("NET0433 AAA settings", NET0433)
    check ("NET0433 AAA authentication settings", NET0433a)
    check ("NET0600 Password Encryption setting", NET0600)
# Service checks
    check ("NET0405 Call Home seeting", NET0405) 
    check_there ("NET0720 TCP/UDP small servers", NET0720)
    check ("NET0722 Service Pad", NET0722)
    check ("NET0724 tcp keep alives in", NET0724)
    check_there ("NET0726 ident service", NET0726)
    check_there ("NET0730 finger service", NET0730)
    check_there ("NET0740 http server", NET0740)
    check_there ("NET0744 BSD rcp-enabled commands", NET0744)
    check_there ("NET0744 BSD rsh-enabled commands", NET0744a)
    check ("NET0740 bootp server", NET0750)
    check ("NET0728 dhcp service", NET0728)
    check_there ("NET0760 no boot network", NET0760)
    check_there ("NET0760 no service config", NET0760)
    check ("NET0781 no Gratuitous ARP", NET0781)
# Loopback Checks
    test ("NET0897 tacacs source Loopback", NET0897)
    test ("NET0897 radius source Loopback", NET0897a)
    test ("NET0898 logging source Loopback", NET0898)
    test ("NET0899 NTP source Loopback", NET0899)
    test ("NET0900 SNMP source Loopback", NET0900)
    test ("NET0901 Netflow source Loopback", NET0901)
# IP Checks 
    test ("NET0960 TCP Intercept", NET0960)
    test ("NET0965 TCP synwait-time", NET0965)
# Banner Check    
    banner_check ()

#####################################################3
    
def interface_checks():
    print "---------------------------------------"
    print "Interface checks"    
    check_interface_config("NET0780 proxy ARP", NET0780)
    check_line()
    check_interface_config("NET0770 ip source routing", NET0770)
    check_interface_config("NET0790 no ip directed-broadcast", NET0790)
    check_interface_config("NET0800 no ip redirects", NET0800)
    check_interface_config("NET0800 no ip unreachables", NET0800)


def IPV6_checks():
    print "---------------------------------------"
    print "IPv6 checks"
    check ("NET-IPV6-033 IPv6 CEF", NET_IPV6_033)
    
def TUNL_checks():
    print "---------------------------------------"
    print "Tunnel checks"
    
def MCAST_checks():
    print "---------------------------------------"
    print "Multicast checks"
    mcast_check()
    
def SRVFRM_checks():
    print "---------------------------------------"
    print "Server Farm checks"
    
def VLAN_checks():
    print "---------------------------------------"
    print "VLAN Checks"
    
def NAC_checks():
    print "---------------------------------------"
    print "NAC checks"
    
# Benchmarks based on STIG checklists
# Infra_router - Infrastructure Router
# Perimeter_router
# Perimeter_L3_switch
# Infra_L3_switch
# L2_switch

def Infra_router():
    print "---------------------------------------"
    print "-PROFILE INFRASTRUCTURE ROUTER CHECKS-"
    
    NET_checks()    
    interface_checks()
    IPV6_checks()
    TUNL_checks()
    MCAST_checks()

def Perimeter_router():
    print "Perimeter Router Checks"
    NET_checks()    
    interface_checks()
    IPV6_checks()
    TUNL_checks()
    MCAST_checks()

def Perimeter_L3_switch():
    print "Perimeter L3 Switch Checks"
    NET_checks()    
    interface_checks()
    IPV6_checks()
    TUNL_checks()
    MCAST_checks()
    SRVFRM_checks()
    VLAN_checks()
    NAC_checks()

def Infra_L3_switch():
    print "Infrastructure L3 Switch Checks"
    NET_checks()    
    interface_checks()
    IPV6_checks()
    TUNL_checks()
    MCAST_checks()
    SRVFRM_checks()
    VLAN_checks()
    NAC_checks()

def L2_switch():
    print "L2 Switch Checks"
    NET_checks()    
    interface_checks()
    VLAN_checks()
    NAC_checks()


# Main starting of script
def start():
    Infra_router()
#    Perimeter_router()
#    Perimeter_L3_switch()
#    Infra_L3_switch()
#    L2_switch()
    print "--------E-N-D--O-F--S-C-R-I-P-T------------------"
    print "\n Total  PASSED: %r" % Passed
    print " Total  FAILED: %r" % Failed
    print " Total      NA: %r" % NA
    print " Total CHECKED: %r" % (Passed + Failed + NA)
    print "\n\n"

# START of the program
start()

