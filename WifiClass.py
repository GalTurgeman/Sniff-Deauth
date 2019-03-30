from sys import *
import urllib2,signal
class Wifi:
    def __init__(self,SSID,BSSID,RSSI,Channel):
        self._SSID = SSID
        self._BSSID = BSSID.upper()
        self._RSSI = RSSI
        self._CHANNEL = Channel
        self._Vendor = self.resolveMac(BSSID)
        self._Clients=[]

    ##setters##
    def setSSID(self,s):
        self._SSID = s
    def setBSSID(self,b):
        self._BSSID = b
    def setRSSI(self,r):
        self._RSSI = r
    ##getters##
    def getClients(self):
        return self._Clients
    def getSSID(self):
        return self._SSID
    def getBSSID(self):
        return self._BSSID
    def getRSSI(self):
        return self._RSSI
    def getpkt(self):
        return self._pkt
    def getNumOfClients(self):
        return len(self._Clients)
    def getVendor(self):
        return self._Vendor
    def getChannel(self):
        return self._CHANNEL
    def setChannel(self,c):
        self._CHANNEL = c

    def resolveMac(self,mac):
        url = 'http://api.macvendors.com/'
        try:
            request = urllib2.urlopen(url + mac)
        except Exception,msg:
            return "N/A"
        else:
            return request.read()
            '''
            url = "http://macvendors.co/api/vendorname/"
            request = urllib.Request(url + mac, headers={'User-Agent': "API Browser"})
            response = urllib.urlopen(request)
            vendor = response.read()
            vendor = vendor.decode("utf-8")
            vendor = vendor[:25]
            return vendor
        except:
            return "N/A"
            '''

    ##for object printing##
    def __str__(self):
        return "SSID: \t%s\t  BSSID: \t%s\t  RSSI: \t%s\t  " % (self._SSID,self._BSSID,self._RSSI)
    ##for compare two object##
    def __cmp__(self,other):
        if self._BSSID < other._BSSID:
            return -1
        elif self._BSSID > other._BSSID:
            return 1
        else:
            return 0
