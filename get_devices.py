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

    ans, _ = srp(request, timeout=2, retry=1)
    result = []

    for _, received in ans:
        result.append([received.psrc, received.hwsrc])

    return result

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

        res.append((net, arp_scan(net)))

    return res



if __name__== "__main__":
    print(devices_on_ifaces())