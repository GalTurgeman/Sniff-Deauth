class Client:
    def __init__(self,ApSSID,BSSID):
        self._ApSSID = ApSSID
        self._BSSID = BSSID
        self._Vendor = self.resolveMac(BSSID)

    ##setters##
    def setSSID(self,s):
        self._SSID = s
    def setBSSID(self,b):
        self._BSSID = b

    ##getters##
    def getSSID(self):
        return self._SSID
    def getBSSID(self):
        return self._BSSID
    def getVendor(self):
        return self._Vendor
    def __str__(self):
        return "AP MAC: %s Client MAC: %s" %(self._ApSSID,self._BSSID)

    def __cmp__(self,other):
        if self._BSSID < other._BSSID:
            return -1
        elif self._BSSID > other._BSSID:
            return 1
        else:
            return 0

    def resolveMac(self,mac):
        url = 'http://api.macvendors.com/'
        try:
            request = urllib2.urlopen(url + mac)
        except:
            return "N/A"
        else:
            return request.read()
