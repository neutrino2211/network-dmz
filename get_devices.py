from tabnanny import verbose
import scapy.config
import scapy.layers.l2
import scapy.route
from scapy.all import Ether, ARP, srp
import math

def long2net(arg):
    if (arg <= 0 or arg >= 0xFFFFFFFF):
        raise ValueError("illegal netmask value", hex(arg))
    return 32 - int(round(math.log(0xFFFFFFFF - arg, 2)))


def to_CIDR_notation(bytes_network, bytes_netmask):
    network = scapy.utils.ltoa(bytes_network)
    netmask = long2net(bytes_netmask)
    net = "%s/%s" % (network, netmask)
    if netmask < 16:
        return None

    return net

def arp_scan(ip):
    request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)

    ans, _ = srp(request, timeout=2, retry=1, verbose = False)
    result = []

    for _, received in ans:
        result.append([received.psrc, received.hwsrc])

    return result

def get_mac(ip):
    arp_request = ARP(pdst = ip)
    broadcast = Ether(dst ="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = srp(arp_request_broadcast, timeout = 5, verbose = False)[0]

    if len(answered_list) == 0:
        print("No answer for", ip)
        return None

    return answered_list[0][1].hwsrc

def devices_on_ifaces():
    # if os.geteuid() != 0:
    #     print('You need to be root to run this script', file=sys.stderr)
    #     sys.exit(1)
    res = []


    for network, netmask, _, interface, address, _ in scapy.config.conf.route.routes:
        
        # skip loopback network and default gw
        if network == 0 or interface == 'lo' or address == '127.0.0.1' or address == '0.0.0.0':
            continue

        if netmask <= 0 or netmask == 0xFFFFFFFF:
            continue

        net = to_CIDR_notation(network, netmask)

        if net == None:
            continue

        print(scapy.config.conf.route.route())

        route = scapy.config.conf.route.route("0.0.0.0")

        devices = [[route[2], get_mac(route[2])]]

        devices.extend(arp_scan(net))

        if len(devices) == 0:
            continue

        res.append((net, devices))

    return res



if __name__== "__main__":
    print(devices_on_ifaces())