import sqlite3
import psutil
import os
import time
import sys
import time
from datetime import datetime, timedelta
import os
import datetime
import whois
from ipwhois import IPWhois
import socket
from socket import AF_INET, SOCK_STREAM, SOCK_DGRAM
import wmi
import nmap
import glob
import dpkt
import optparse
import socket
from scapy.all import *

#------Helper database functions------------

#run db command ex: update, delete, insert
def runCommand(db, query):
    try:
        conn = sqlite3.connect(db)
        conn.execute(query)
        conn.commit()
        #print "Total number of rows affected :", conn.total_changes
        conn.close()
    except:
        print "Error run command"

#get single string return from DB
def selectFromDBReturnSingleString(db,query):
    try:
        conn = sqlite3.connect(db);
        cursor = conn.execute(query);
        data="";
        for row in cursor:
           data= row[0];
        conn.close();
        return data;
    except:
        return "";

# check to see if database exists    
def validateDB(db):
    try:
        conn = sqlite3.connect(db)
        print "Opened database successfully";
        conn.close();
        return 1;
    except:
        return 0;

#convert size
def convert_bytes(n):
    symbols = ('K', 'M', 'G', 'T', 'P', 'E', 'Z', 'Y')
    prefix = {}
    for i, s in enumerate(symbols):
        prefix[s] = 1 << (i+1)*10
    for s in reversed(symbols):
        if n >= prefix[s]:
            value = float(n) / prefix[s]
            return '%.1f%s' % (value, s)
    return "%sB" % n
 
#custom display print out  
def print_(a, b):
    if sys.stdout.isatty() and os.name == 'posix':
        fmt = '\x1b[1;32m%-17s\x1b[0m %s' %(a, b)
    else:
        fmt = '%-15s %s' %(a, b)
    sys.stdout.write(fmt + '\n')
    sys.stdout.flush()

def secs2hours(secs):
    mm, ss = divmod(secs, 60)
    hh, mm = divmod(mm, 60)
    return "%d:%02d:%02d" % (hh, mm, ss)

#------End Helper database functions----------

#-------SYSTEM INFORMATION----------

def whoislookup():
    data = raw_input("Enter a domain or IP: ");
    domain = whois.whois(data)
    print domain
    try:
        from warnings import filterwarnings
        filterwarnings( action="ignore")
        from ipwhois import IPWhois
        from pprint import pprint
        obj = IPWhois(data)
        results = obj.lookup_whois(inc_nir=True)
        pprint(results)
    except:
        print ""
#get process list
def GetProcessList():
    option= raw_input("Display childen processes? ('1' for no, '2' for yes, '3' for yes and recursively)>>  ");
    for proc in psutil.process_iter():
        try:
            pinfo = proc.as_dict();
            pid=pinfo['pid']
            name=pinfo['name']
            exe=pinfo['exe']
            try:
                cmdline=''.join(pinfo['cmdline'])
            except:
                cmdline=""
            status=pinfo['status'];
            user= pinfo['username'];
            create_time=datetime.datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
            print pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline,"  ",exe
            if(option=="2" or option =="3"):
                if(option=="3"):
                    children = proc.children(recursive=True)
                else:
                    children = proc.children(recursive=False)
                for child in children:
                    try:
                       pinfo = child.as_dict();
                       pid=pinfo['pid']
                       name=pinfo['name']
                       exe=str(pinfo['exe']).replace("None","")
                       try:
                            cmdline=''.join(pinfo['cmdline'])
                       except:
                            cmdline=""
                       status=pinfo['status'];
                       user= pinfo['username'];
                       if cmdline=="None" or cmdline=="":
                            cmdline=exe
                       create_time=datetime.datetime.fromtimestamp(child.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                       print "      Child: ",pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline
                    except psutil.NoSuchProcess:
                        pass
        except psutil.NoSuchProcess:
            pass

def GetCurrentSystemConnections():
    AD = "-" 
    AF_INET6 = getattr(socket, 'AF_INET6', object()) 
    proto_map = { (AF_INET, SOCK_STREAM): 'tcp', (AF_INET6, SOCK_STREAM): 'tcp6', (AF_INET, SOCK_DGRAM): 'udp', (AF_INET6, SOCK_DGRAM): 'udp6'} 

    templ = "%-5s %-30s %-30s %-13s %-6s %s"
    proc_names = {}
    for p in psutil.process_iter():
        try:
            proc_names[p.pid] = p.name()
        except psutil.Error:
            pass
    for c in psutil.net_connections(kind='all'):
        laddr = "%s:%s" % (c.laddr)
        raddr = ""
        if c.raddr:
            raddr = "%s:%s" % (c.raddr)
        print(templ % (
            proto_map[(c.family, c.type)],
            laddr,
            raddr or AD,
            c.status,
            c.pid or AD,
            proc_names.get(c.pid, '?')[:15],
        )) 

#search for a process and display detail information about a process  
def processSearch():
    pidstr= raw_input("Get detail information from PID or name. Type \"exit\" to end search.>>  ");
    try:
        pid=int(pidstr);
    except:
        pid=-1;
    ACCESS_DENIED = ''
    while (pidstr.lower() !="exit"):
        print "\n",80 * "-"
        for p in psutil.process_iter():
            curentpid=p.pid;
            processname=p.name();
            if curentpid==pid or processname.lower() ==pidstr.lower()  or  pidstr.lower()  in processname.lower() :
                pinfo = p.as_dict();
                started = datetime.datetime.fromtimestamp(pinfo['create_time']).strftime('%Y-%M-%d %H:%M')
                io = pinfo.get('io_counters', None)
                mem = '%s%% (resident=%s, virtual=%s) ' % (round(pinfo['memory_percent'], 1),convert_bytes(pinfo['memory_info'].rss),convert_bytes(pinfo['memory_info'].vms))
                print_('pid:', pinfo['pid'])
                print_('name:', pinfo['name'])
                print_('exe:', pinfo['exe'])
                try:
                    print_('cmdline:', ''.join(pinfo['cmdline']))
                except:
                    print_('cmdline:', ' ')
                print_('started:', started)
                print_('user:', pinfo['username'])
                if os.name == 'posix':
                    print_('uids:', 'real=%s, effective=%s, saved=%s' % pinfo['uids'])
                    print_('gids:', 'real=%s, effective=%s, saved=%s' % pinfo['gids'])
                    print_('terminal:', pinfo['terminal'] or '')
                if hasattr(p, 'getcwd'):
                    print_('cwd:', pinfo['cwd'])
                print_('memory:', mem)
                print_('cpu:', '%s%% (user=%s, system=%s)' % (pinfo['cpu_percent'], pinfo['cpu_times'].user, pinfo['cpu_times'].system))
                print_('status:', pinfo['status'])
                print_('niceness:', pinfo['nice'])
                print_('num threads:', pinfo['num_threads'])
                if io != ACCESS_DENIED:
                    print_('I/O:', 'bytes-read=%s, bytes-written=%s' %  (convert_bytes(io.read_bytes), convert_bytes(io.write_bytes)))
            
                #get parent of the process
                try:
                    parent=p.parent();
                    ppinfo = parent.as_dict();
                    pid=ppinfo['pid']
                    name=ppinfo['name']
                    exe=str(ppinfo['exe']).replace("None","")
                    try:
                        cmdline=''.join(ppinfo['cmdline'])
                    except:
                        cmdline=""
                    status=ppinfo['status'];
                    user= ppinfo['username'];
                    create_time=datetime.datetime.fromtimestamp(parent.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                    print "Parent: ",pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline,"  ",exe
                except:
                    print ""

                #get all children of the process
                print_('Children processes:', '\n')
                children = p.children(recursive=True)
                for child in children:
                    try:
                       cpinfo = child.as_dict();
                       pid=cpinfo['pid']
                       name=cpinfo['name']
                       exe=str(cpinfo['exe']).replace("None","")
                       try:
                            cmdline=''.join(cpinfo['cmdline'])
                       except:
                            cmdline=""
                       status=cpinfo['status'];
                       user= cpinfo['username'];
                       create_time=datetime.datetime.fromtimestamp(child.create_time()).strftime("%Y-%m-%d %H:%M:%S")
                       print "      Child: ",pid,"  ",name,"  ",status,"  ",create_time,"  ",cmdline,"  ",exe
                    except psutil.NoSuchProcess:
                        pass

                #get all open files
                if pinfo['open_files'] != ACCESS_DENIED:
                    print_('Open files:', ' ')
                    try:
                        for file in pinfo['open_files']:
                            try:
                                print_('',  'fd=%s %s ' % (file.fd, file.path))
                            except:
                                print "" 
                    except:
                        print "" 

                #get all running threads
                if pinfo['threads']:
                    print_('Running threads:', ' ')
                    try:
                        for thread in pinfo['threads']:
                            try:
                                print_('',  'id=%s, user-time=%s, sys-time=%s' % (thread.id, thread.user_time, thread.system_time))
                            except:
                                print ""
                    except:
                        print "" 

                #get all open running threads
                if pinfo['connections'] != ACCESS_DENIED:
                    print_('Open running threads:', ' ')
                    try: 
                        for conn in pinfo['connections']:
                            try:
                                if conn.type == socket.SOCK_STREAM:
                                    type = 'TCP'
                                elif conn.type == socket.SOCK_DGRAM:
                                    type = 'UDP'
                                else:
                                    type = 'UNIX'
                                lip, lport = conn.local_address
                                if not conn.remote_address:
                                    rip, rport = '*', '*'
                                else:
                                    rip, rport = conn.remote_address
                                print_('',  '%s:%s -> %s:%s type=%s status=%s' % (lip, lport, rip, rport, type, conn.status))
                            except:
                                print ""   
                    except:
                        print ""

                #get connections
                print_('Open connections:', ' ')
                AF_INET6 = getattr(socket, 'AF_INET6', object())
                AD = "-"
                proto_map = {(AF_INET, SOCK_STREAM)  : 'tcp', (AF_INET6, SOCK_STREAM) : 'tcp6', (AF_INET, SOCK_DGRAM)   : 'udp', (AF_INET6, SOCK_DGRAM)  : 'udp6'}
                templ = "%-5s %-30s %-30s %-13s" 
                print(templ % ("Proto", "Local address", "Remote address", "Status"))
                try:
                    conns = p.get_connections(kind="all")
                except:
                    conns = p.connections(kind="all")
                for c in conns:
                    laddr = "%s:%s" % (c.laddr)
                    raddr = ""  
                    if c.raddr:  
                        raddr = "%s:%s" % (c.raddr)  
                    print(templ % (proto_map[(c.family, c.type)], laddr, raddr or AD, c.status))
                print "\n",80 * "-"
        pidstr= raw_input("Get detail information from PID or name. Type \"exit\" to end search.>>  ");
        try:
            pid=int(pidstr);
        except:
            pid=-1;
        ACCESS_DENIED = '' 
              
def computerInformation():
    try:
        print "System CPU times" , 30 * "-","\n"
        print psutil.cpu_times()
    except:
        print ""
    try:
        print "Number of logical CPUs in the system" , 30 * "-","\n" 
        print psutil.cpu_count()
    except:
        print ""
    try:        
        print "Number of usable CPUs" , 30 * "-","\n"
        print len(psutil.Process().cpu_affinity())
    except:
        print ""
    try:          
        print "CPU statistics" , 30 * "-","\n" 
        print psutil.cpu_stats()
    except:
        print ""
    try:          
        print "CPU frequency" , 30 * "-","\n" 
        print psutil.cpu_freq()
    except:
        print ""
    try:          
        print "Statistics about system memory" , 30 * "-","\n"
        print psutil.virtual_memory()
    except:
        print ""
    try:           
        print "System swap memory statistics" , 30 * "-","\n" 
        print psutil.swap_memory()
    except:
        print ""
    try:           
        print "Mounted disk partitions" , 30 * "-","\n" 
        print psutil.disk_partitions()
    except:
        print ""
    try:            
        print "Disk usage statistics" , 30 * "-","\n" 
        print psutil.disk_usage('/')
    except:
        print ""
    try:           
        print "System-wide disk I/O statistics" , 30 * "-","\n" 
        print psutil.disk_io_counters()
    except:
        print ""
    try:            
        print "System-wide network I/O statistics" , 30 * "-","\n" 
        print psutil.net_io_counters()
    except:
        print ""
    try:            
        print "System-wide socket connections" , 30 * "-","\n" 
        print psutil.net_connections()
    except:
        print ""
    try:           
        print "The addresses associated to each NIC" , 30 * "-","\n" 
        print psutil.net_if_addrs()
    except:
        print ""
    try:           
        print "Information about each NIC" , 30 * "-","\n" 
        print psutil.net_if_stats()
    except:
        print ""
    try:            
        print "Hardware temperatures" , 30 * "-","\n"
        print psutil.sensors_temperatures()
    except:
        print ""
    try:           
        print "Hardware fans speed" , 30 * "-","\n"
        print psutil.sensors_fans()
    except:
        print ""
    try:           
        print "Battery status information" , 30 * "-","\n" 
        battery = psutil.sensors_battery()
        print battery
        print("charge = %s%%, time left = %s" % (battery.percent, secs2hours(battery.secsleft)))
    except:
        print ""
    try:            
        print "System boot time" , 30 * "-","\n" 
        print psutil.boot_time()
    except:
        print ""
    try:            
        print "Users currently connected on the system" , 30 * "-","\n" 
        print psutil.users()
    except:
        print ""
    try:           
        print "Current running PIDs" , 30 * "-","\n"
        print psutil.pids()
    except:
        print ""
#-------End System Information------

#Read Event Log
def readEventLog(db):
    #handle various connection (local or remote computer) and with our without credential
    try:
        runCommand(db, "DELETE FROM EventLog");
        remoteName= raw_input("Computer Name (Blank for localhost): >>  ");
        username=""
        passwrd=""
        if remoteName!="":
            username= raw_input("Username (Blank for current credential): >>  ");
            passwrd= raw_input("Password (Blank for current credential): >>  ");
        c = wmi.WMI()
        if remoteName!="" and username!="":
            c = wmi.WMI(remoteName)
        elif remoteName!="":
            rmuser=remoteName+"\\"+username
            c = wmi.WMI(remoteName, user=rmuser, password=passwrd)        
        #conn = sqlite3.connect(db)
        print "Type of event: 1. Error, 2.Warning, 3. Information, 4. Security Audit Success, 5. Security Audit Failure"
        type= raw_input("Please select type of event:");
        print "Log file type: 1. System, 2.Application, 3. Security"
        typelogfile= raw_input("Please select Log file type:");
        if(typelogfile=="1"):
            typelogfile="System"
        elif(typelogfile=="2"):
            typelogfile="Application"
        elif(typelogfile=="3"):
            typelogfile="Security"
        else:
            typelogfile=""
        print "Please wait";
        for log in c.Win32_NTLogEvent(EventType=int(type), Logfile=typelogfile):
            query="insert into EventLog (ComputerName,LogFile,RecordNumber,Type,EventCode,Message,TimeGenerated) values ('"+remoteName+"','"+log.Logfile+"','"+str(log.RecordNumber)+"','"+log.Type+"','"+str(log.EventCode)+"','"+str(log.Message).replace("'","''")+"','"+str(log.TimeGenerated)+"')"
            print str(log.RecordNumber)+" - "+log.Type
            runCommand(db, query)
        #conn.close()
    except:
        print "Invalid Input";

#finding out various parts of a system
def getWMIInfo():
    #handle various connection (local or remote computer) and with our without credential
    remoteName= raw_input("Computer Name (Blank for localhost): >>  ");
    username=""
    passwrd=""
    if remoteName!="":
        username= raw_input("Username (Blank for current credential): >>  ");
        passwrd= raw_input("Password (Blank for current credential): >>  ");
    c = wmi.WMI()
    if remoteName!="" and username!="":
        c = wmi.WMI(remoteName)
    elif remoteName!="":
        rmuser=remoteName+"\\"+username
        c = wmi.WMI(remoteName, user=rmuser, password=passwrd)
    
    #classes
    print 80 * "-"
    print "Hierarchy of classes\n"
    print 80 * "-"
    print c.Win32_Process.derivation() 
    for extrinsic_event in c.subclasses_of("__ExtrinsicEvent", "[^_].*"):
        print extrinsic_event
        print "  ", " < ".join(getattr(c, extrinsic_event).derivation())

    #groups on system and which users are in each group
    print 80 * "-"
    print "Group\n"
    print 80 * "-"
    for group in c.Win32_Group():
        print group.Caption
        for user in group.associators(wmi_result_class="Win32_UserAccount"):
            print "  User:", user.Caption

    #OS information
    print 80 * "-"
    print "OS Information\n"
    print 80 * "-"
    for os in c.Win32_OperatingSystem():
        print os.Caption

    #Method produces its function signature
    print 80 * "-"
    print "Method Information\n"
    print 80 * "-"
    for method_name in os.methods: 
        method = getattr(os, method_name)
        print method

    #Disk information
    print 80 * "-"
    print "Fixed disks\n"
    print 80 * "-"
    for disk in c.Win32_LogicalDisk(DriveType=3):
        print disk
    print 80 * "-"
    print "Non-Fixed disks\n"
    print 80 * "-"
    wql = "SELECT Caption, Description FROM Win32_LogicalDisk WHERE DriveType <> 3"
    for disk in c.query(wql):
        print disk

#find information about a pcap
def PcapAnalyzer(db):
    print "1.Clear Report Data\n2.Analyze Package\n3.Report\n4.Exit"
    choice= raw_input("Please select an option: ");
    while choice!="4":
        if choice=="1":
            runCommand(db, "DELETE FROM PCAP");
            runCommand(db, "DELETE FROM DNSRecords");            
        elif choice=="2":
            dirr = raw_input("pcap directory: ");
            if dirr=="":
               dirr="C:\Python27\Tools"
            for r, d, f in os.walk(dirr):
                for file in f:
                    if ".pcap" in file:
                        pcapFile=os.path.join(r,file)
                        print pcapFile;
                        #pcapFile=raw_input("specify pcap filename: >>  ");
                        f = open(pcapFile, 'rb')
                        pcap = dpkt.pcap.Reader(f)
                        findConnections(pcap,db)
                        pkts = rdpcap(pcapFile)
                        #get how many ips for each domain name
                        dnsRecords = {}
                        for pkt in pkts:  
                            if pkt.haslayer(DNSRR):
                                rrname = pkt.getlayer(DNSRR).rrname
                                rdata = pkt.getlayer(DNSRR).rdata
                                if dnsRecords.has_key(rrname):
                                    if rdata not in dnsRecords[rrname]:
                                        dnsRecords[rrname].append(rdata)
                                else:
                                    dnsRecords[rrname] = []
                                    dnsRecords[rrname].append(rdata)
                        for item in dnsRecords:
                            query="insert into DNSRecords (Item,IPsCount) values ('"+item+"','"+str(len(dnsRecords[item]))+"')"
                            runCommand(db, query)
        elif choice=="3":
            conn = sqlite3.connect(db)
            cursor = conn.execute("SELECT src,dst,dport,sport,pktsSent,InfoType from PCAP where InfoType='Downloaded LOIC' order by pktsSent desc")
            print 30 * "-","Downloaded LOIC",30 * "-","\n"
            for row in cursor:
                print str(row[0]),' send to ',str(row[1]),' port ' , str(row[2]),' '+str(row[3]),' pkts.\n'
            print 80 * "-","\n"
            cursor = conn.execute("SELECT src,dst,dport,sport,pktsSent,InfoType from PCAP where InfoType='DDoS Hivemind issued' order by pktsSent desc")
            print 30 * "-","DDoS Hivemind issued",30 * "-","\n"
            for row in cursor:
                print str(row[0]),' send to ',str(row[1]),' port ' , str(row[2]),' '+str(row[3]),' pkts.\n'
            print 80 * "-","\n"
            cursor = conn.execute("SELECT src,dst,dport,sport,pktsSent,InfoType from PCAP where InfoType='Package Send' order by pktsSent desc")
            print 30 * "-","Package Send",30 * "-","\n"
            for row in cursor:
                print str(row[0]),' send to ',str(row[1]),' port ' , str(row[2]),' '+str(row[3]),' pkts.\n'
            print 80 * "-","\n"
            cursor = conn.execute("SELECT Item,IPsCount from DNSRecords order by IPsCount desc")
            print 30 * "-","DNS Records",30 * "-","\n"
            for row in cursor:
                print row[0]+' has '+row[1] +' unique IPs.'
            print 80 * "-","\n"
            conn.close()
        else: 
            print "Invalid selection"
        print "1.Clear Report Data\n2.Analyze Package\n3.Report\n4.Exit"
        choice= raw_input("Please select an option:");   

#find how many time a connection being request from a package
def findConnections(pcap,db):
    pktCount = {}
    for (ts, buf) in pcap:
        try:
            eth = dpkt.ethernet.Ethernet(buf)
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            tcp = ip.data
            dport = tcp.dport
            sport = tcp.sport
            try:
                http = dpkt.http.Request(tcp.data)
                if http.method == 'GET':
                    uri = http.uri.lower()
                    if '.zip' in uri and 'loic' in uri:#Low Orbit Ion Cannon (LOIC) used for network stress testing, denial of service (DoS) and distributed denial of service (DDoS) attacks.
                        query="insert into PCAP (src,dst,dport,sport,InfoType) values ('"+src+"','"+dst+"','"+str(dport)+"','"+str(sport)+"','"+"Downloaded LOIC"+"')"
                        runCommand(db, query)
            except:
                pass
            if dport == 6667 or sport==6667:
                if '!lazor' in tcp.data.lower():
                    query="insert into PCAP (src,dst,dport,sport,InfoType) values ('"+src+"','"+dst+"','"+str(dport)+"','"+str(sport)+"','"+"DDoS Hivemind issued"+"')"
                    runCommand(db, query)
            stream = src + ':' + dst+ ':'+str(dport)+ ':'+str(sport)
            if pktCount.has_key(stream):
               pktCount[stream] = pktCount[stream] + 1
            else:
               pktCount[stream] = 1
        except:
            pass
    for stream in pktCount:
        pktsSent = pktCount[stream]
        src = stream.split(':')[0]
        dst = stream.split(':')[1]
        dport = stream.split(':')[2]
        sport =stream.split(':')[3]
        query="insert into PCAP (src,dst,dport,sport,pktsSent,InfoType) values ('"+src+"','"+dst+"','"+str(dport)+"','"+str(sport)+"','"+str(pktsSent)+"','"+"Package Send"+"')"
        #print query
        runCommand(db, query)

#menu options display and selection
def menu(db,type):
    
    conn = sqlite3.connect(db)
    cursor = conn.execute("SELECT text, value from MenuOptions where type= '"+type+"' order by DisplayOrder")
    print 30 * "-" , type , 30 * "-"
    for row in cursor:
       print row[1],".  ", row[0], "\n"
    print 80 * "-"
    conn.close()

    option = raw_input("Please enter your selection: >>  ")
    query="SELECT text from MenuOptions where type= '"+type+"' and value='"+option+"' order by DisplayOrder"
    try:
        selection=selectFromDBReturnSingleString(db,query);
    except:
        selection=""
    while selection=="":
        print "Invalid selection!"
        option = raw_input("Please enter your selection: >>  ")
        query="SELECT text from MenuOptions where type= '"+type+"' and value='"+option+"' order by DisplayOrder"
        try:
            selection=selectFromDBReturnSingleString(db,query);
        except:
            selection=""   
    if(selection=="MAIN MENU" or selection=="COMPUTER INFORMATION" or selection=="NETWORK"):
        if(selection=="MAIN MENU"):
            os.system('cls')
        menu(db,selection);
    elif(selection=="LIST RUNNING PROCESSES"):
        GetProcessList();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SEARCH FOR A PROCESS"):
        processSearch();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SYSTEM INFORMATION"):
        computerInformation();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SYSTEM CONNECTIONS"):
        GetCurrentSystemConnections();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="WHO IS LOOKUP"):
        whoislookup();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="SYSTEM SCAN"):
        getCurrentSystemNetwork();
        menu(db,"COMPUTER INFORMATION");
    elif(selection=="EVENT LOG"):
        readEventLog(db);
        menu(db,"NETWORK");
    elif(selection=="SCAN PCAP"):
        PcapAnalyzer(db);
        menu(db,"NETWORK");
    elif(selection=="WMI INFORMATION"):
        getWMIInfo();
        menu(db,"NETWORK");
    elif(selection=="EXIT"):
        print "Thank you for using my program. Have a great day!";

# main prompt for database connection
if __name__ == '__main__':
    db = raw_input("Please enter database location (blank for default) >>  ")
    if(db==""):
        db = "C:\Python27\SecurityTool.db"
    validDB=validateDB(db)
    while validDB==0:
        db = raw_input("Please enter database location (blank for default) >>  ")
        if(db==""):
            db = "C:\Python27\SecurityTool.db"
        validDB=validateDB(db)
    menu(db,"MAIN MENU")


