import os
import sys
import ipaddress

def is_ip_valid(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

def service_handle():
    os.system("nft -f /etc/nftables.conf")

def default_rules(filename):
    TR_LINE = ['type filter hook input priority',
                'type filter hook forward priority',
                'type filter hook output priority']
    
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    
    W_FILE = open(filename, 'w')

    for line in CONTENT:
        for MATCH  in TR_LINE:
            if MATCH in line:
                SP_LINE=line.split()[-1]
                if SP_LINE == "filter;":
                    line = "\t\t"+MATCH+" 0;\n"
        W_FILE.write(line)
    W_FILE.close()

def allow_all_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=True
    i=1
    W_FILE = open(filename, 'w')
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=True
        
        if Flag:
            W_FILE.write(line)
            
        if i==2:
            Flag=False
            i=i+1
    W_FILE.close()
    service_handle()

def allow_incoming_port_connection(filename, port_list):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=True
    i=1
    W_FILE = open(filename, 'w')
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            line = line+"\t\ttcp dport {"
            for port in port_list:
                line = line+port+", "
            line = line[:-2]+"} accept\n\t\tpolicy drop;\n"
            i=i+1
        if "\t}" in line:
            Flag=True
        
        if Flag:
            W_FILE.write(line)
            
        if i==2:
            Flag=False
            i=i+1
    W_FILE.close()

def block_incoming_port_connection(filename, port_list):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=True
    i=1
    W_FILE = open(filename, 'w')
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            line = line+"\t\ttcp dport {"
            for port in port_list:
                line = line+port+", "
            line = line[:-2]+"} drop\n\t\tpolicy accept;\n"
            i=i+1
        if "\t}" in line:
            Flag=True
        
        if Flag:
            W_FILE.write(line)
            
        if i==2:
            Flag=False
            i=i+1
    W_FILE.close()

def allow_all_outgoing_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=True
    i=1
    W_FILE = open(filename, 'w')
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=True
        
        if Flag:
            W_FILE.write(line)
            
        if i==2:
            Flag=False
            i=i+1
    W_FILE.close()
    service_handle()

def view_all_allowd_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "accept" in line:
                line = line.replace("ip saddr {", "")
                line = line.replace("} accept", "")
                line = line.replace("\t", "")
                print("allowed incoming connection ::: {}".format(line))         
        if i==2:
            Flag=True
            i=i+1

def view_all_allowd_port_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "tcp dport" in line and "accept" in line:
                line = line.replace("tcp dport {", "")
                line = line.replace("} accept", "")
                line = line.replace("\t", "")
                print("allowed incoming connection ::: {}".format(line))         
        if i==2:
            Flag=True
            i=i+1
        
def block_all_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=True
    i=1
    W_FILE = open(filename, 'w')
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            line = line+"\t\tpolicy drop;\n"
            i=i+1
        if "\t}" in line:
            Flag=True
        
        if Flag:
            W_FILE.write(line)
            
        if i==2:
            Flag=False
            i=i+1
    W_FILE.close()
    service_handle()

def block_all_outgoing_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=True
    i=1
    W_FILE = open(filename, 'w')
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            line = line+"\t\tpolicy drop;\n"
            i=i+1
        if "\t}" in line:
            Flag=True
        
        if Flag:
            W_FILE.write(line)
            
        if i==2:
            Flag=False
            i=i+1
    W_FILE.close()
    service_handle()

def view_all_blocked_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "drop" in line:
                line = line.replace("ip saddr {", "")
                line = line.replace("} drop", "")
                line = line.replace("\t", "")
                print("blocked incoming connection ::: {}".format(line))         
        if i==2:
            Flag=True
            i=i+1

def view_all_blocked_port_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "tcp dport" in line and "drop" in line:
                line = line.replace("tcp dport {", "")
                line = line.replace("} drop", "")
                line = line.replace("\t", "")
                print("blocked incoming connection ::: {}".format(line))         
        if i==2:
            Flag=True
            i=i+1

def view_all_allowd_outgoing_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "accept" in line:
                line = line.replace("ip saddr {", "")
                line = line.replace("} accept", "")
                line = line.replace("\t", "")
                print("allowed outgoing connection ::: {}".format(line))         
        if i==2:
            Flag=True
            i=i+1

def view_all_blocked_outgoing_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "drop" in line:
                line = line.replace("ip saddr {", "")
                line = line.replace("} drop", "")
                line = line.replace("\t", "")
                print("blocked outgoing connection ::: {}".format(line))         
        if i==2:
            Flag=True
            i=i+1

def add_allowd_incoming_connection(filename, ip_list):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, 'w')
    alm=1
    m=1
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        elif "\t}" in line and m==2:
            new_data="\t\tip saddr {"
            for ip in ip_list:
                if ip not in new_data:
                    new_data = new_data+ip+", "
            line = new_data[:-2]+"} accept\n\t\tpolicy drop;\n\t}\n"
            m=m+1
            Flag=False
        elif "\t}" in line:
            Flag=False
        
        if Flag:
            m=m+1
            if "ip saddr {" in line and "} accept" in line:
                alm=alm+1
                data = line.split("} accept")
                new_data = data[0]
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+", "+ip
                line= new_data+"} accept\n"
            elif "drop" in line and alm==1:
                new_data = "\t\tip saddr {"
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+ip+", "
                line = new_data[:-2]+"} accept\n\t\tpolicy drop;\n"
            elif "accept" in line:
                line=""
        W_FILE.write(line)
        if i==2:
            Flag=True
            i=i+1
            m=m+1
    W_FILE.close()
    service_handle()


def add_blocked_incoming_connection(filename, ip_list):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, 'w')
    alm=1
    m=1
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        elif "\t}" in line and m==2:
            new_data="\t\tip saddr {"
            for ip in ip_list:
                if ip not in new_data:
                    new_data = new_data+ip+", "
            line = new_data[:-2]+"} drop\n\t\tpolicy accept;\n\t}\n"
            m=m+1
            Flag=False
        elif "}\n" in line:
            Flag=False
        
        if Flag:
            m=m+1
            if "ip saddr {" in line and "} drop" in line:
                alm=alm+1
                data = line.split("} drop")
                new_data = data[0]
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+", "+ip
                line= new_data+"} drop\n"
            elif "accept" in line and alm==1:
                new_data = "\t\tip saddr {"
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+ip+", "
                line = new_data[:-2]+"} drop\n\t\tpolicy accept;\n"
            elif "drop" in line:
                line=""
                alm=alm+1
        W_FILE.write(line)
        if i==2:
            Flag=True
            i=i+1
            m=m+1
    W_FILE.close()
    service_handle()

def remove_ip_from_allowd_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, "w")
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "accept" in line:
                line1 = line.replace("ip saddr {", "")
                line1 = line1.replace("} accept", "")
                line1 = line1.replace("\t", "")
                line1 = line1.replace("\n", "")
                print("allowed incoming connection ::: {}".format(line1))  
                print("you can enter multiple ip's seprate by space")
                input_ip = input("Enter ip that you want to remove : ") 
                input_ip = input_ip.split(" ")
                for ip in input_ip:
                    if ip in line:
                        line = line.replace(ip+", ", "")
                        line = line.replace(", "+ip, "")
        if i==2:
            Flag=True
            i=i+1
        W_FILE.write(line)
        service_handle()
        
def remove_ip_from_blocked_incoming_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, "w")
    for line in CONTENT:
        if "type filter hook input priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "drop" in line:
                line1 = line.replace("ip saddr {", "")
                line1 = line1.replace("} drop", "")
                line1 = line1.replace("\t", "")
                line1 = line1.replace("\n", "")
                print("blocked incoming connection ::: {}".format(line1))  
                print("you can enter multiple ip's seprate by space")
                input_ip = input("Enter ip that you want to remove : ") 
                input_ip = input_ip.split(" ")
                for ip in input_ip:
                    if ip in line:
                        line = line.replace(ip+", ", "")
                        line = line.replace(", "+ip, "")
        if i==2:
            Flag=True
            i=i+1
        W_FILE.write(line)
        service_handle()

def remove_ip_from_allowd_outgoing_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, "w")
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "accept" in line:
                line1 = line.replace("ip saddr {", "")
                line1 = line1.replace("} accept", "")
                line1 = line1.replace("\t", "")
                line1 = line1.replace("\n", "")
                print("allowed outgoing connection ::: {}".format(line1))  
                print("you can enter multiple ip's seprate by space")
                input_ip = input("Enter ip that you want to remove : ") 
                input_ip = input_ip.split(" ")
                for ip in input_ip:
                    if ip in line:
                        line = line.replace(ip+", ", "")
                        line = line.replace(", "+ip, "")
        if i==2:
            Flag=True
            i=i+1
        W_FILE.write(line)
        service_handle()

def remove_allowed_incoming_port(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    
    W_FILE = open(filename, "w")
    for line in CONTENT:
        if "tcp dport" in line and "accept" in line:
            line = ""
        W_FILE.write(line)
    W_FILE.close()
    service_handle()

def remove_allowed_incoming_port(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    
    W_FILE = open(filename, "w")
    for line in CONTENT:
        if "tcp dport" in line and "drop" in line:
            line = ""
        W_FILE.write(line)
    W_FILE.close()
    service_handle()

def remove_ip_from_blocked_outgoing_connection(filename):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, "w")
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        if "\t}" in line:
            Flag=False
        
        if Flag:
            if "ip saddr" in line and "drop" in line:
                line1 = line.replace("ip saddr {", "")
                line1 = line1.replace("} drop", "")
                line1 = line1.replace("\t", "")
                line1 = line1.replace("\n", "")
                print("blocked incoming connection ::: {}".format(line1))  
                print("you can enter multiple ip's seprate by space")
                input_ip = input("Enter ip that you want to remove : ") 
                input_ip = input_ip.split(" ")
                for ip in input_ip:
                    if ip in line:
                        line = line.replace(ip+", ", "")
                        line = line.replace(", "+ip, "")
        if i==2:
            Flag=True
            i=i+1
        W_FILE.write(line)
        service_handle()
    
def add_allowd_outgoing_connection(filename, ip_list):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, 'w')
    alm=1
    m=1
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        elif "\t}" in line and m==2:
            new_data="\t\tip saddr {"
            for ip in ip_list:
                if ip not in new_data:
                    new_data = new_data+ip+", "
            line = new_data[:-2]+"} accept\n\t\tpolicy drop;\n\t}\n"
            m=m+1
            Flag=False
        elif "\t}" in line:
            Flag=False
        
        if Flag:
            m=m+1
            if "ip saddr {" in line and "} accept" in line:
                alm=alm+1
                data = line.split("} accept")
                new_data = data[0]
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+", "+ip
                line= new_data+"} accept\n"
            elif "drop" in line and alm==1:
                new_data = "\t\tip saddr {"
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+ip+", "
                line = new_data[:-2]+"} accept\n\t\tpolicy drop;\n"
            elif "accept" in line:
                line=""
        W_FILE.write(line)
        if i==2:
            Flag=True
            i=i+1
            m=m+1
    W_FILE.close()
    service_handle()

def add_blocked_outgoing_connection(filename, ip_list):
    with open(filename, 'r') as R_FILE:
        CONTENT = R_FILE.readlines()
    Flag=False
    i=1
    W_FILE = open(filename, 'w')
    alm=1
    m=1
    for line in CONTENT:
        if "type filter hook output priority 0;" in line:
            i=i+1
        elif "\t}" in line and m==2:
            new_data="\t\tip saddr {"
            for ip in ip_list:
                if ip not in new_data:
                    new_data = new_data+ip+", "
            line = new_data[:-2]+"} drop\n\t\tpolicy accept;\n\t}\n"
            m=m+1
            Flag=False
        elif "}\n" in line:
            Flag=False
        
        if Flag:
            m=m+1
            if "ip saddr {" in line and "} drop" in line:
                alm=alm+1
                data = line.split("} drop")
                new_data = data[0]
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+", "+ip
                line= new_data+"} drop\n"
            elif "accept" in line and alm==1:
                new_data = "\t\tip saddr {"
                for ip in ip_list:
                    if ip not in new_data:
                        new_data = new_data+ip+", "
                line = new_data[:-2]+"} drop\n\t\tpolicy accept;\n"
            elif "drop" in line:
                line=""
                alm=alm+1
        W_FILE.write(line)
        if i==2:
            Flag=True
            i=i+1
            m=m+1
    W_FILE.close()
    service_handle()

def home_logo():
    print("""
        ####   ##     ##      ###        #####      #######     #######
         ##    ##     ##     ## ##      ##   ##    ##     ##   ##     ##
         ##    ##     ##    ##   ##    ##     ##   ##     ##   ##     ##
         ##    #########   ##     ##   ##     ##    #######     ########
         ##    ##     ##   #########   ##     ##   ##     ##          ##
         ##    ##     ##   ##     ##    ##   ##    ##     ##   ##     ##
        ####   ##     ##   ##     ##     #####      #######     #######

IHA089: Navigating the Digital Realm with Code and Security - Where Programming Insights Meet Cyber Vigilance.
    """)
    print("This tool is design for own system security")


def help():
    print("Usage: acon <flag> <filter>")
    print("\tabout                     about tool devloper")
    print("\t-h                        for help")
    print("\t-a in                     allow all incoming connection")
    print("\t-b in                     block all incoming connection")
    print("\t-a in <ip1> <ip2> ...     allow specific ip's for incoming connection")
    print("\t-b in <ip1> <ip2> ...     block specific ip's for incoming connection")
    print("\t-a removein               remove ip from allow incoming ip list")
    print("\t-b removein               remove ip from block incoming ip list")
    print("\t-a viewin                 view all allowed incoming connection ip")
    print("\t-b viewin                 view all blocked incoming connection ip")
    print("\t-a out                    allow all outgoing connection")
    print("\t-b out                    block all outgoing connection")
    print("\t-a out <ip1> <ip2> ...    allow specific ip's for outgoing connection")
    print("\t-b out <ip1> <ip2> ...    block specific ip's for outgoing connection")
    print("\t-a viewout                view all allowed outgoing connection")
    print("\t-b viewout                view all blocked outgoing connection")
    print("\t-a removeout              remove ip from allowed outgoing ip list")
    print("\t-b removeout              remove ip from blocked outgoing ip list")
    print("\t-p <port1> <port2> ...    allow specific ports")
    print("\t-q <port1> <port2> ...    block specific ports")
    print("\t-p remove                 remove port from allow port list")
    print("\t-q remove                 remove  port from block port list")
    print("\t-p view                   view all allowed ports")
    print("\t-q view                   view all blocked ports")




def Main():
    ARG_LEN = len(sys.argv)
    filename="/etc/nftables.conf"
    if len(sys.argv) == 1:
        print("For more information\nUsage: acon -h")
    elif sys.argv[1] == "-h":
        help()
    elif sys.argv[1] == "about":
        home_logo()
    elif sys.argv[1] == "-a":
        default_rules(filename)
        if len(sys.argv) == 2:
            print("Please check help")
        elif sys.argv[2] == "in":
            if len(sys.argv) == 3:
                allow_all_incoming_connection(filename)
                print("All incoming connection allowed")
            else:
                ip_list=[]
                for i in range(3, len(sys.argv)):
                    if is_ip_valid(sys.argv[i]):
                        ip_list.append(sys.argv[i])
                    else:
                        print("Usage: acon -a in 192.168.1.234 127.0.0.1")
                        print("Please check help for more information")
                        sys.exit()
                add_allowd_incoming_connection(filename, ip_list)
        elif sys.argv[2] == "removein":
            remove_ip_from_allowd_incoming_connection(filename)
        elif sys.argv[2] == "removeout":
            remove_ip_from_allowd_outgoing_connection(filename)
        elif sys.argv[2] == "out":
            if len(sys.argv) == 3:
                allow_all_outgoing_connection(filename)
                print("All outgoing connection allowed")
            else:
                ip_list=[]
                for i in range(3, len(sys.argv)):
                    if is_ip_valid(sys.argv[i]):
                        ip_list.append(sys.argv[i])
                    else:
                        print("Usage: acon -a out 192.168.1.234 127.0.0.1")
                        print("Please check help for more information")
                        sys.exit()
                    add_allowd_outgoing_connection(filename, ip_list)
        elif sys.argv[2] == "viewin":
            view_all_allowd_incoming_connection(filename)
        elif sys.argv[2] == "viewout":
            view_all_allowd_outgoing_connection(filename)
            

    elif sys.argv[1] == "-b":
        default_rules(filename)
        if len(sys.argv) == 2:
            print("Please check help")
        elif sys.argv[2] == "in":
            if len(sys.argv) == 3:
                block_all_incoming_connection(filename)
                print("All incoming connection blocked")
            else:
                ip_list=[]
                for i in range(3, len(sys.argv)):
                    if is_ip_valid(sys.argv[i]):
                        ip_list.append(sys.argv[i])
                    else:
                        print("Usage: acon -b 192.168.1.234 127.0.0.1")
                        print("Please check help for more information")
                        sys.exit()
                add_blocked_incoming_connection(filename, ip_list)
        elif sys.argv[2] == "removein":
            remove_ip_from_blocked_incoming_connection(filename)
        elif sys.argv[2] == "removeout":
            remove_ip_from_allowd_outgoing_connection(filename)
        elif sys.argv[2] == "out":
            if len(sys.argv) == 3:
                block_all_outgoing_connection(filename)
                print("All outgoing connection blocked")
        elif sys.argv[2] == "viewin":
            view_all_blocked_incoming_connection(filename)
        elif sys.argv[2] == "viewout":
            view_all_blocked_outgoing_connection(filename)
    elif sys.argv[1] == "-p":
        default_rules(filename)
        if len(sys.argv) == 2:
            print("Please check help")
        elif sys.argv[2] == "remove":
            remove_allowed_incoming_port(filename)
        elif sys.argv[2] == "view":
            view_all_allowd_port_incoming_connection(filename)
        else:
            port_list=[]
            for i in range(2, len(sys.argv)):
                port_list.append(sys.argv[i])
            allow_incoming_port_connection(filename, port_list)
    elif sys.argv[1] == "-q":
        default_rules(filename)
        if len(sys.argv) == 2:
            print("Please check help")
        elif sys.argv[2] == "remove":
            remove_blocked_incoming_port(filename)
        elif sys.argv[2] == "view":
            view_all_allowd_port_incoming_connection(filename)
        else:
            port_list=[]
            for i in range(2, len(sys.argv)):
                port_list.append(sys.argv[i])
            block_incoming_port_connection(filename, port_list)

if __name__ == "__main__":
    Main()
