import socket, glob, json

port = 53
ip = '127.0.0.1'

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
sock.bind((ip, port))

def load_zones():

    jsonzone = {}
    zonefiles = glob.glob('zones/*.zone')

    for zone in zonefiles:
        with open(zone) as zonedata:
            data = json.load(zonedata)
            zonename = data["$origin"]
            jsonzone[zonename] = data
    
    return jsonzone

zonedata = load_zones()

def get_flags(flags):
    
    byte1 = bytes(flags[:1])
    byte2 = bytes(flags[1:2])

    resflags = ''

    QR = '1'

    OPCODE = ''

    for bit in range(1,5):
        OPCODE += str(ord(byte1)&(1<<bit))

    AA = '1'

    TC = '0'

    RD = '0'

    # Byte 2

    RA = '0'

    Z = '000'

    RCODE = '0000'

    return (int(QR + OPCODE + AA + TC + RD, 2).to_bytes(1, byteorder = 'big') + int(RA + Z + RCODE, 2).to_bytes(1, byteorder = 'big'))

def get_question_domain(data):

    state = 0
    expectedlength = 0
    domainstring = ''
    domainparts = []
    x = 0
    y = 0

    for byte in data:
        if state == 1:
            if byte != 0:
                domainstring += chr(byte)
            x += 1
            if x == expectedlength:
                domainparts.append(domainstring)
                domainstring = ''
                state = 0
                x = 0
            if byte == 0:
                domainparts.append(domainstring)
                break
        else:
            state = 1
            expectedlength = byte
        
        y += 1

    questiontype = data[y: y + 2]

    return (domainparts, questiontype)

def get_zone(domain):
    global zonedata

    zone_name = '.'.join(domain)
    return zonedata[zone_name]

def get_recs(data):
    domain, questiontype = get_question_domain(data)
    qt = ''
    if questiontype == b'\x00\x01':
        qt = 'a'

    zone = get_zone(domain)

    return (zone[qt], qt, domain)


def build_response(data):

    # Transaction ID
    TransactionID = data[:2]
     
    # Get the Flags
    Flags = get_flags(data[2:4])

    # Question Count
    QDCOUNT = b'\x00\x01'

    # Answer Count
    ANCOUNT = len(get_recs(data[12:][0])).to_bytes(2, byteorder = 'big')
    print(ANCOUNT)

    # Nameserver Count
    NSCOUNT = (0).to_bytes(2, byteorder = 'big')

    # Additional Count
    ARCOUNT = (0).to_bytes(2, byteorder = 'big')

    dnsheader = (TransactionID + Flags + QDCOUNT + ANCOUNT + NSCOUNT + ARCOUNT)

    print(dnsheader)

while 1:
    data, addr = sock.recvfrom(512)
    r = build_response(data)
    sock.sendto(r, addr)
