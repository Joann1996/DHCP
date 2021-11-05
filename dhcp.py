
from datetime import datetime
import os
import struct
import base64
import sys
from threading import *
from socket import *
import time


lock =Lock()

shortunpack = lambda data: (data[0] << 8) + data[1]
shortpack = lambda i: bytes([i >> 8, i & 255])

def macunpack(data):
    s = base64.b16encode(data)
    return ':'.join([s[i:i+2].decode('ascii') for i in range(0, 12, 2)])


dhcp_message_types = {
    1 : 'DHCPDISCOVER',
    2 : 'DHCPOFFER',
    3 : 'DHCPREQUEST',
    4 : 'DHCPDECLINE',
    5 : 'DHCPACK',
    6 : 'DHCPNAK',
    7 : 'DHCPRELEASE',
    8 : 'DHCPINFORM',
}
reversed_dhcp_message_types = dict()
for i, v in dhcp_message_types.items():
    reversed_dhcp_message_types[v] = i


def compute_available_number(mask_part):
    if mask_part == 0:
        return 255
    mask_part -= 128
    if mask_part <= 0:
        return 127
    mask_part -= 64
    if mask_part <= 0:
        return 63
    mask_part -= 32
    if mask_part <= 0:
        return 31
    mask_part -= 16
    if mask_part <= 0:
        return 15
    mask_part -= 8
    if mask_part <= 0:
        return 7
    mask_part -= 4
    if mask_part <= 0:
        return 3
    return 0

def request_ip_and_mask():
    network_ip = [0, 0, 0, 0]
    mask = [0, 0, 0, 0]
    network_ip = input("entrez l'ip réseau: ").split(".")
    mask = input("entrez le masque de sous réseau: ").split(".")
    network_string=".".join(network_ip)
    mask_string=".".join(mask)
    for i in range(len(network_ip)):
        network_ip[i] = int(network_ip[i])
    for i in range(len(mask)):
        mask[i] = int(mask[i])
    return network_ip,mask,network_string,mask_string

def compute_available_number_list(mask):
    i = 0
    available_number = []
    while (i < 4):
        available_number.append(compute_available_number(mask[i]))
        i += 1
    return available_number

def compute_addresses(network_ip,mask,available_number):
    available_ip = []
    for a in range(network_ip[0], network_ip[0] + available_number[0] + 1):
        for b in range(network_ip[1], network_ip[1] + available_number[1] + 1):
            for c in range(network_ip[2], network_ip[2] + available_number[2] + 1):
                for d in range(network_ip[3], network_ip[3] + available_number[3] + 1):
                    if ([a, b, c, d] == network_ip or [a, b, c, d] == [network_ip[0] + available_number[0],
                                                                       network_ip[1] + available_number[1],
                                                                       network_ip[2] + available_number[2],
                                                                       network_ip[3] + available_number[3]]):
                        continue
                    available_ip.append(str(a) + "." + str(b) + "." + str(c) + "." + str(d))
    return available_ip
dns_list=None
gateway=None
network_ip,mask,network_string,mask_string=None,None,None,None
interface=None
lease_time=None
try:
    with open('dhcp_conf','r') as file:
        for line in file.read().split('\n'):
            if 'network ip: ' in line:
                network_string =line.split(": ")[1]
                network_ip = network_string.split(".")
                for i in range(len(network_ip)):
                    network_ip[i] = int(network_ip[i])
            if 'mask: ' in line:
                mask_string =line.split(": ")[1]
                mask = mask_string.split(".")
                for i in range(len(mask)):
                    mask[i] = int(mask[i])
            if 'interface: ' in line:
                interface =line.split(": ")[1]
            if 'dns: ' in line:
                dns_list =line.split(": ")[1].split(", ")
            if 'gateway: ' in line:
                gateway =line.split(": ")[1]
            if 'lease time: 'in line:
                lease_time=int(line.split(': ')[1])
        file.close()
except Exception as e:
    print('file not found')

if network_ip==None or mask==None or interface==None or dns_list==None or gateway==None or lease_time==None:
    print("file not correct")
    network_ip, mask, network_string, mask_string = request_ip_and_mask()
    interface = input("nom de l'inteface?: ")
    dns_list = input("entrez la liste des dns à utiliser (ex:a.a.a.a, b.b.b.b): ").split(", ")
    gateway = input("entrez l'addresse de la gateway: ")
    lease_time=int(input("entrez le lease time(86400= 1 jour): "))

available_number=compute_available_number_list(mask)
available_ip=compute_addresses(network_ip,mask,available_number)
print("ip disponibles:\n"+str(available_ip))
given_ip=dict()
server_ip=available_ip.pop(0)
given_ip["server_ip"]=[server_ip,0]
os.system("ifconfig "+interface +" "+server_ip+" netmask "+mask_string)
os.system("route add default "+ interface)
print("ip server:\n"+str(server_ip))
dns_byte_list=[]
for ips in dns_list:
    dns_byte_list+=inet_aton(ips)



def read_option(param,data):
    index = 240
    while index < len(data):
        option = data[index]
        index += 1
        if option == 0:
            continue
        if option == 255:
            break
        option_length = data[index]
        index += 1
        option_data = data[index: index + option_length]
        index += option_length
        if option == param:
            return option_data
    return 0


def respond_to_discovery(msg):
    print("responding to discovery")
    response = bytearray(236)
    response[0] = 2
    response[1] = msg[1]
    response[2] = msg[2]
    response[3] = msg[3]

    response[4:8] =xid = msg[4:8]

    response[8:10] = shortpack(0)
    response[10:12] = shortpack(0)

    response[12:16] = inet_aton("0.0.0.0")
    requested_ip=read_option(50,msg)
    if requested_ip!=0:
        if inet_ntoa(requested_ip) in available_ip:
            your_ip_address= available_ip.pop(available_ip.index(inet_ntoa(requested_ip)))
        else:
            your_ip_address=available_ip.pop(0)
    else:
        your_ip_address = available_ip.pop(0)
    try:
        name = read_option(12, msg).decode('ASCII')
    except:
        name=None
    if name!=None:
        given_ip[name]=[your_ip_address,lease_time]
    else:
        given_ip[macunpack(msg[4:8])] = [your_ip_address,lease_time]
    response[16:20] = inet_aton(your_ip_address)
    response[20:24] = inet_aton(server_ip)
    response[24:28] = inet_aton(gateway)

    response[28:28 +msg[2]] = msg[28: 28 + msg[2]]

    response += inet_aton("99.130.83.99")
    i=240
    option = 53
    response += bytes([option, 1]) + bytes([2])
    option= 1
    response += bytes([option, len(inet_aton(mask_string))]) + inet_aton(mask_string)
    option= 3
    response += bytes([option, len(inet_aton(server_ip))]) + inet_aton(server_ip)
    option= 54
    response += bytes([option, len(inet_aton(server_ip))]) + inet_aton(server_ip)
    option= 51
    response += bytes([option, len(struct.pack('>I', lease_time))]) +struct.pack('>I', lease_time)
    option= 6
    response += bytes([option, len(bytes(dns_byte_list))]) + bytes(dns_byte_list)
    response += bytes([255])
    lock.acquire()
    try:
        broadcastsock = socket(type=SOCK_DGRAM)
        broadcastsock.bind(("", 68))
        broadcastsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
        broadcastsock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
        broadcastsock.sendto(bytes(response), ("255.255.255.255", 68))
        broadcastsock.close()
        with open('log.txt', 'a') as f:
            res_message = msg_type(msg)
            type_of_message = dhcp_message_types[res_message]
            f.write(str(datetime.now()) + " dhcpd: " + type_of_message + " for %s" %(inet_ntoa(requested_ip) if requested_ip!=0 else "any ip") + " from " + name + " via " + interface + "\n"
                    +str(datetime.now())+" offered "+ your_ip_address+"\n" )
    except Exception as e:
        print(e)
    lock.release()


def is_discovery(type):
    return type==reversed_dhcp_message_types['DHCPDISCOVER']


def msg_type(data):
    if data[0]==1:
        index = 240
        while index < len(data):
            option = data[index]
            index += 1
            if option == 0:
                continue
            if option == 255:
                break
            option_length = data[index]
            index += 1
            option_data = data[index: index + option_length]
            index += option_length
            if option == 53:
                return option_data[0]
    return 0


def is_request(type):
    return type==reversed_dhcp_message_types['DHCPREQUEST']




def respond_to_request( msg ):
    print("responding to request")
    response = bytearray(236)
    response[0] = 2
    response[1] = msg[1]
    response[2] = msg[2]
    response[3] = msg[3]

    response[4:8] = request_xid= msg[4:8]
    try:
        name = read_option(12, msg).decode('ASCII')
    except:
        name = None
    if request_xid in given_ip.keys() or name in given_ip.keys():
        response[8:10] = shortpack(0)
        response[10:12] = shortpack(0)

        response[12:16] = inet_aton("0.0.0.0")
        if name != None:
            your_ip_address = given_ip[name][0]
            given_ip[name][1]=lease_time
        else:
            your_ip_address = given_ip[msg[4:8]][0]
            given_ip[macunpack(msg[4:8])][1] = lease_time
        response[16:20] = inet_aton(your_ip_address)
        response[20:24] = inet_aton(server_ip)
        response[24:28] = inet_aton(gateway)

        response[28:28 + msg[2]] = msg[28: 28 + msg[2]]

        response += inet_aton("99.130.83.99")
        i = 240
        option = 53
        response += bytes([option, 1]) + bytes([5])
        option = 1
        response += bytes([option, len(inet_aton(mask_string))]) + inet_aton(mask_string)
        option = 3
        response += bytes([option, len(inet_aton(server_ip))]) + inet_aton(server_ip)
        option = 54
        response += bytes([option, len(inet_aton(server_ip))]) + inet_aton(server_ip)
        option = 51
        response += bytes([option, len(struct.pack('>I', lease_time))]) + struct.pack('>I', lease_time)
        option = 6
        response += bytes([option, len(bytes(dns_byte_list))]) + bytes(dns_byte_list)
        response += bytes([255])

        lock.acquire()
        try:
            broadcastsock = socket(type=SOCK_DGRAM)
            broadcastsock.bind(("", 68))
            broadcastsock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
            broadcastsock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
            broadcastsock.sendto(bytes(response), ("255.255.255.255", 68))
            broadcastsock.close()
            with open('log.txt', 'a') as f:
                res_message = msg_type(msg)
                type_of_message = dhcp_message_types[res_message]
                f.write(str( datetime.now()) + " dhcpd: " + type_of_message + " for " + your_ip_address + " from " + name + " via " + interface + "\n"
                        +str( datetime.now()) + " sent ACK\n")
        except Exception as e:
            print(e)
        lock.release()
        return True
    else:
        print("refusé")
        lock.acquire()
        try:
            name=read_option(12,msg).decode('ASCII')
            anonymous=False
        except Exception as e:
            print(e)
            print("option 12")
            print(read_option(12,msg))
            name = macunpack(msg[28: 28 + msg[2]])
            anonymous = True
        with open('log.txt', 'a') as f:
            res_message = msg_type(msg)
            type_of_message = dhcp_message_types[res_message]
            f.write(str(
                datetime.now()) + " dhcpd: " + type_of_message + " from %s refused\n" %(name if anonymous==False else "anonymous, mac address = "+name))
        lock.release()
        return False


def wait_for_discovery(serversocket):
    while True:
        msg,addr=serversocket.recvfrom(4096)
        type=msg_type(msg)
        print(" new message, type = " + dhcp_message_types[type])
        if is_discovery(type):
            if len(enumerate())<10:
                Thread(target=respond_to_discovery,args=(msg,)).start()
            else:
                print("too many threads")
                for thr in enumerate():
                    thr.join()
        elif is_request(type):
            if len(enumerate())<10:
                Thread(target=respond_to_request, args=(msg,)).start()
            else:
                print("too many threads")
                for thr in enumerate():
                    thr.join()

def lease_time_checking():
    while True:
        time.sleep(1)
        if len(given_ip.keys())>1:
            keys = []
            for key in given_ip.keys():
                keys.append(key)
            for machines in keys:
                if given_ip[machines][1] != 0:
                    given_ip[machines][1]-=1
                    if given_ip[machines][1] == 0:
                        ip = given_ip[machines][0]
                        available_ip.append(ip)
                        given_ip.pop(machines)


serversock = socket(type=SOCK_DGRAM)
serversock.bind(("", 67))
serversock.setsockopt(SOL_SOCKET, 25, interface.encode("ASCII"))
serversock.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
serversock.setsockopt(SOL_SOCKET, SO_BROADCAST, 1)
waiting=Thread(target=wait_for_discovery,args=(serversock,))
lease_checker = Thread(target=lease_time_checking)
lease_checker.daemon=True
lease_checker.start()
waiting.daemon=True
waiting.start()
print("commands\n ip list -> get the list of available ip\n distributed -> get the list of distributed ip\n exit or kill -> end programm\n")
while True:
    command=input("command line: ")
    if command=="ip list":
        print(available_ip)
    if command=="distributed":
        print(given_ip)
    if command=="kill" or command=="exit":
        sys.exit()