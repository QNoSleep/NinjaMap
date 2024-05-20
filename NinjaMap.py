import sys 
import os
import time
import signal
from time import sleep
from sys import argv
from platform import system

defaultportscan = "45"

def scannermenu():
    print("\033[1;92m YOUR OUTPUT IS IN YOUR CURRENT DIRECTORY\033[1;m")
    print("")
    print("\033[1;91m 1-) Back to the Main Menu \n 2-) Exit! \033[1;m")

    choicemap = input("root""\033[1;91m@NinjaMap:~$\033[1;m ")
    if choicemap == "1":
        os.system("clear")
        nscan()
    elif choicemap == "2":
        os.system("clear")
        print(" \033[1;91m@ALLAH'a emanet ol !!\033[1;m")
        sys.exit()
    else:
        print("Please chose one of the options that I give you :)\n You are directed to the main menu!")
        time.sleep(2)
        os.system("clear")
        nscan()

def sigint_handler(signum, frame):
    os.system("clear")
    print(" \033[1;91m@ALLAH'a emanet ol !!\033[1;m")
    sys.exit()

signal.signal(signal.SIGINT, sigint_handler)
os.system("clear")

def logo():
    print(r"""
    ############################################
    #  ___  _   _      ____  _                 #
    # / _ \| \ | | ___/ ___|| | ___  ___ _ __  #
    #| | | |  \| |/ _ \___ \| |/ _ \/ _ | '_ \ #
    #| |_| | |\  | (_) ___) | |  __|  __| |_) |#
    # \__\_|_| \_|\___|____/|_|\___|\___| .__/ #
    #                                   |_|    #
    ############################################
        """)
def menu():
    logo()
    outputs = os.popen("pwd").read().strip()
    user = os.popen("whoami").read().strip()
    capitilized_user = user.upper()
    print(f"\033[1;91m HELLO MY DEAR FRIEND\033[1;m '''{capitilized_user}''' your outputs are here: \n{outputs}")
    print("""
    1-) Normal Scanning
    2-) Firewall Bypass
    3-) Vulnerability Scanning
    00-) Contact
    0-) Exit
    """)

def nscan():
    menu()

    choice = input("root""\033[1;91m@NinjaMap:~$\033[1;m ")

    os.system("clear")
    if choice == "1":
        dscan()
    elif choice == "2":
        firewallscan()
    elif choice == "3":
        vul()
    elif choice == "00":
        credit()
    elif choice == "0":
        exit()
    elif choice == "":
        menu()
    else:
        print("Please enter one of the options in the menu. \n You are directed to the main menu.")
        time.sleep(2)
        os.system("clear")
        nscan()

def dscan():
    os.system("clear")
    logo()
    print("""
        1-) Default Scan
        2-) Host Discovery
        3-) Port(SYN) Scan
        4-) Port(TCP) Scan
        5-) Port(UDP) Scan
        6-) Null scan (-sN)
        7-) FIN scan (-sF)
        8-) OS Analysis and Version Discovery
        9-) Nmap Script Engineering (default)
        00-) Back to Menu
          """)
    
    choice_of_dscan = input("root""\033[1;91m@NinjaMap:~$\033[1;m ")
    os.system("clear")
    if choice_of_dscan == "1":
        os.system("clear")
        ds()
    elif choice_of_dscan == "2":
        os.system("clear")
        hd()
    elif choice_of_dscan == "3":
        os.system("clear")
        synscan()
    elif choice_of_dscan == "4":
        os.system("clear")
        tcpscan()
    elif choice_of_dscan == "5":
        os.system("clear")
        udpscan()
    elif choice_of_dscan == "6":
        os.system("clear")
        nullscan()
    elif choice_of_dscan == "7":
        os.system("clear")
        finscan()
    elif choice_of_dscan == "8":
        os.system("clear")
        oav()
    elif choice_of_dscan == "9":
        os.system("clear")
        ns()
    elif choice_of_dscan == "00":
        os.system("clear")
        nscan()
    else:
        ConnectionAbortedError

def firewallscan():
    os.system("clear")
    logo()
    print("""
    1-) Script Bypass (--script=firewall-bypass)
    2-) Data Length   (--data-length <number>)
    3-) Smash
    00-) Back to Menu
""")
    choice_of_firewallscan = input("root""\033[1;91m@NinjaMap:~$\033[1;m ")
    os.system("clear")

    if choice_of_firewallscan == "1":
        os.system("clear")
        sb()
    elif choice_of_firewallscan == "2":
        os.system("clear")
        dl()
    elif choice_of_firewallscan == "3":
        os.system("clear")
        smash()
    elif choice_of_firewallscan == "00":
        nscan()
    else:
        ConnectionAbortedError

def vul():
    os.system("clear")
    logo()
    print("""
    1-) Default Vuln Scan (--script vuln)
    2-) FTP Vuln Scan
    3-) SMB Vuln Scan
    4-) HTTP Vuln Scan
    5-) SQl Injection Vuln Scan
    6-) Stored XSS Vuln Scan
    7-) Dom Based XSS Vuln Scan
    00-) Back To Menu
    """)

    choicevul = input("root""\033[1;91m@NinjaMap:~$\033[1;m ")
    os.system("clear")
    if choicevul == "1":
        os.system("clear")
        dvs()
    elif choicevul == "2":
        os.system("clear")
        ftpvulnScan()   
    elif choicevul == "3":
        os.system("clear")
        smbvulnScan()
    elif choicevul == "4":
        os.system("clear")
        httpvulnScan()
    elif choicevul == "5":
        os.system("clear")
        sqlvulnScan()
    elif choicevul == "6":
        os.system("clear")
        storedxssScan()
    elif choicevul == "7":
        os.system("clear")
        domxssScan()
    elif choicevul == "00":
        os.system("clear")
        nscan()

    

def ds():
    print(" Starting Default Scan...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_one = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_one:
            os.system("nmap -vv --top-ports="+defaultportscan+" "+target+" -oN "+target)
        else:
            os.system("nmap -vv --top-ports="+topport_one+" "+target+" -oN "+target)
    scannermenu()

def hd():
    print("Starting The Host Discovery...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_second = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_second:
            os.system("nmap -vv -Pn --top-ports="+defaultportscan+" "+target+" -oN HostD-"+target+"-ouptut")
        else:
            os.system("nmap -vv -Pn --top-ports="+topport_second+" "+target+" -oN HostD-"+target+"-output")
        scannermenu()

def synscan():
    print("Starting The Port(SYN) Scan...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_third = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_third:
            os.system("nmap -vv -sS --top-ports="+defaultportscan+" "+target+" -oN "+target+"-output")
        else:
            os.system("nmap -vv -sS --top-ports="+topport_third+" "+target+" -oN"+target+"-output")
        scannermenu()

def tcpscan():
    print("Starting The Port(TCP) Scan...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_fourth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_fourth:
            os.system("nmap -vv -sT --top-ports="+defaultportscan+" "+target+" -oN TcpScan"+target+"-output")
        else:
            os.system("nmap -vv -sT --top-ports="+topport_fourth+" "+target+" -oN TcpScan"+target+"-output")
        scannermenu()

def udpscan():
    print("Starting The Port(UDP) Scan...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_fifth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_fifth:
            os.system("nmap -vv -sU --top-ports="+defaultportscan+" "+target+" -oN UdpScan"+target+"-output")
        else:
            os.system("nmap -vv -sU --top-ports="+topport_fifth+" "+target+" -oN UdpScan"+target+"-output")
        scannermenu()

def nullscan():
    print("Starting The Null Scan -sN ...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_sixth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_sixth:
            os.system("nmap -vv -sN --top-ports="+defaultportscan+" "+target+" -oN NullScan"+target+"-output")
        else:
            os.system("nmap -vv -sN --top-ports="+topport_sixth+" "+target+" -oN NullScan"+target+"-output")
        scannermenu()

def finscan():
    print("Starting The FIN scan -sF ...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_seventh = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_seventh:
            os.system("nmap -vv -sF --top-ports="+defaultportscan+" "+target+" -oN FinScan"+target+"-output")
        else:
            os.system("nmap -vv -sF --top-ports="+topport_seventh+" "+target+" -oN FinScan"+target+"-output")
        scannermenu()

def oav():
    print("Starting OS and Version Discovery...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        os.system("clear")
        nscan()
    else:
        topport_eighth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_eighth:
            os.system("nmap -sS -sV --top-ports="+defaultportscan+" "+target+" -oN Os-Version"+target+"-output")
        else:
            os.system("nmap -sS -sV --top-ports="+topport_eighth+" "+target+" -oN Os-Version"+target+"-output")
        scannermenu()

def ns():
    print("Starting Nmap Script Engineering...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_ninth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_ninth:
            os.system("nmap -sS --script=default --top-ports="+defaultportscan+" "+target+" -oN ScScan"+target+"-output")
        else:
            os.system("nmap -sS --script=default --top-ports="+topport_ninth+" "+target+" -oN ScScan"+target+"-output")
        scannermenu()

# Firewall Bypass Section !

def sb():
    print("Starting Nmap Firewall Bypass...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_tenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_tenth:
            os.system("nmap -vv --script=firewall-bypass --top-ports="+defaultportscan+" "+target+" -oN firewallbypass"+target+"-output")
        else:
            os.system("nmap -vv --script=firewall-bypass --top-ports="+topport_tenth+" "+target+" -oN firewallbypass"+target+"-output")
        scannermenu()
def dl():
    print("Starting Data Length...")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033[1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_eleventh = input("What is the port ? Example: 30 - 50, Default is 45: ")
        print("Random data to sent packets..")
        datalength=input("Number: ")
        if not topport_eleventh:
            os.system("nmap --data-string "+datalength+" --top-ports="+defaultportscan+" "+target+" -oN datalength"+target+"-output")
        else:
            os.system("nmap --data-string "+datalength+" --top-ports="+topport_eleventh+" "+target+" -oN datalength"+target+"-output")
        scannermenu()

def smash():
    print("Smash (-ff) ")
    time.sleep(1)
    os.system("clear")
    logo()
    print(" Please Enter the IP Adress (0.0.0.0) or example.com")
    print("")
    target = input("Enter your Target: ")
    if not target:
        print("Please Enter the Target: ")
        print("\033[1;91m What is your problem ? Head back to the main menu now.. \033 [1;m]]")
        time.sleep(2)
        os.system("clear")
        nscan()
    else:
        topport_twelfth = input("What is the port ? Example: 30 - 50, Default is 45: ")
        if not topport_twelfth:
            os.system("nmap -vv -ff --top-ports="+defaultportscan+" "+target+" -oN ff"+target+"-output")
        else:
            os.system("nmap -vv -ff --top-ports="+topport_twelfth+" "+target+" -oN ff"+target+"-output")
        scannermenu()

#Vulnerability Scan !



def dvs():
        print("Default Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_thirtheenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_thirtheenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script vuln " +target+" -oN "+"VulnScanDef-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_thirtheenth+" --script vuln " +target+" -oN "+"VulnScanDef-"+target+"-output" )
        
        nscan()



def ftpvulnScan():
        print("FTP Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_fourteenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_fourteenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script ftp " +target+" -oN "+"FtpVulnScan-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_fourteenth+" --script ftp " +target+" -oN "+"FtpVulnScan-"+target+"-output" )
        
        nscan()

def smbvulnScan():
        print("SMB Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_fifteenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_fifteenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script smb " +target+" -oN "+"SmbVulnScan-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_fifteenth+" --script smb " +target+" -oN "+"SmbVulnScan-"+target+"-output" )
        nscan()

def httpvulnScan():
        print("HTTP Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_sixteenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_sixteenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script smb* " +target+" -oN "+"HTTPVulnScan-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_sixteenth+" --script smb* " +target+" -oN "+"HTTPVulnScan-"+target+"-output" )
        nscan()

def sqlvulnScan():
        print("SQL Injection/Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_seventeenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_seventeenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script=http-sql-injection " +target+" -oN "+"SqlVulnScan-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_seventeenth+" --script=http-sql-injection " +target+" -oN "+"SqlVulnScan-"+target+"-output" )
        nscan()

def storedxssScan():
        print("Stored XSS Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_eigthteenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_eigthteenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script=http-soted-xss.nse" +target+" -oN "+"StoredXSSVulnScan-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_eigthteenth+" --script=http-soted-xss.nse" +target+" -oN "+"StoredXSSVulnScan-"+target+"-output" )
        nscan()

def domxssScan():
        print("DOM XSS Vuln Scan.... ")
        time.sleep(1)
        os.system("clear")
        logo()
        print("     Enter your IP address (0.0.0.0) or example.com")
        print("")
        target = input(" Enter Your Target: ")
        if not target:
            print("Pls Enter Target")
            print("\033[1;91mYou are grounded! You go to the main menu...\033[1;m")
            time.sleep(2)
            os.system("clear")
            nscan()
        else:
            topport_nineteenth = input("What is the port ? Example: 30 - 50, Default is 45: ")
            if not topport_nineteenth:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+defaultportscan+" --script=http-dombased-xss.nse" +target+" -oN "+"DomXSSVulnScan-"+target+"-output" )
            else:
                os.system("nmap -vv -sV -ff -Pn --top-ports="+topport_nineteenth+" --script=http-dombased-xss.nse" +target+" -oN "+"DomXSSVulnScan-"+target+"-output" )
        nscan()

def credit():
        print ("""\033[1;91m
            --____------------_-------------_---
            -/-___|___--_-__-|-|_-__-_--___|-|_-
            |-|---/-_-\|-'_-\|-__/-_`-|/-__|-__|
            |-|__|-(_)-|-|-|-|-||-(_|-|-(__|-|_-
            -\____\___/|_|-|_|\__\__,_|\___|\__|
          ===================================== 
         NOTE : For Back To Menu Press 1 OR For Exit Press 2
      ==========================================================                                                                   
        \033[1;m """)
        
        print("""[!] Mail: \033[1;91m0Xd0000:)0@gmail.com\033[1;m\n
                 [!] Instagram: \033[1;91mhttps://instagram.com/??????\033[1;m\n     
                 [!] Web Site: \033[1;91mhttps://????????????\033[1;m\n   
                 [!] Github: \033[1;91mhttps://github.com/???????\033[1;m\n   
                 [!] Twitter: \033[1;91mhttps://twitter.com/??????????\033[1;m\n\n """)
        choicedonus = input("root""\033[1;91m@Credit:~$\033[1;m ")
        if choicedonus == "1":
            os.system("clear")
            nscan()
        if choicedonus == "2":
            os.system("clear")
            print(" \033[1;91mAllaha Emanet Ol :)\033[1;m")
            sys.exit() 
        else:
            print(" Please enter one of the options in the menu. \n You are directed to the main menu.")
            time.sleep(2)
            os.system("clear")
            nscan()

def rootcontrol():
    if os.getuid() == 0:
        nscan()
    else:
        print("You need to be root for full access. 'type sudo python3 NinjaMap.py'")
        sys.exit()

rootcontrol()










































