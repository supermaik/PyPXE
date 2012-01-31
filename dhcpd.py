#!/usr/bin/env python
#dhcpd.py pure python dhcp server
#pxe capable
import socket, IN, binascii, time, fcntl, struct
from sys import exit

iface_listen = 'eth1.101'

def get_ip_address(ifname):
   s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
   return socket.inet_ntoa(fcntl.ioctl(
      s.fileno(),
      0x8915,  # SIOCGIFADDR
      struct.pack('256s', ifname[:15])
   )[20:24])
   
host = ''
port = 67

print "Listening on " + host + ":" + str(port)

serverhost=str(get_ip_address(iface_listen))
offerfrom='192.168.101.100'
offerto='192.168.101.150'
subnetmask='255.255.255.0'
broadcast='192.168.101.255'
router=''
   
dnsserver=''
leasetime=86400 #int
   
tftpserver='192.168.101.1'
pxefilename='/netboot/pxelinux.0'

leases=[]
#next line creates the (blank) leases table. This probably isn't necessary.
for ip in ['192.168.101.'+str(x) for x in range(int(offerfrom[offerfrom.rfind('.')+1:]),int(offerto[offerto.rfind('.')+1:])+1)]:
   leases.append([ip,False,'000000000000',0])

def release(): #release a lease after timelimit has expired
   for lease in leases:
      if not lease[1]:
         if time.time()+leasetime == leasetime:
             continue
         if lease[-1] > time.time()+leasetime:
            print "Released lease for:",lease[0]
            lease[1]=False
            lease[2]='000000000000'
            lease[3]=0

def getlease(hwaddr): #return the lease of mac address, or create if doesn't exist
   global leases
   for lease in leases:
      if hwaddr == lease[2]:
         return lease[0]
   for lease in leases:
      if not lease[1]:
         lease[1]=True
         lease[2]=hwaddr
         lease[3]=time.time()
         return lease[0]

s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
s.setsockopt(socket.SOL_SOCKET, IN.SO_BINDTODEVICE, iface_listen+'\0')
s.bind((host, port))
#s.sendto(data,(ip,port))

dhcpfields=[1,1,1,1,4,2,2,4,4,4,4,6,10,192,4,"msg.rfind('\xff')",1,None]
def slicendice(msg,slices=dhcpfields): #generator for each of the dhcp fields
   for x in slices:
      if str(type(x)) == "<type 'str'>": x=eval(x) #really dirty, deals with variable length options
      yield msg[:x]
      msg = msg[x:]

def reqparse(message): #handles either DHCPDiscover or DHCPRequest
   #using info from http://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
   #the tables titled DHCPDISCOVER and DHCPOFFER
   data=None
   #send: boolean as to whether to send data back, and data: data to send, if any
   #print len(message)
   hexmessage=binascii.hexlify(message)
   messagesplit=[binascii.hexlify(x) for x in slicendice(message)]
   dhcpopt=messagesplit[15][:6] #hope DHCP type is first. Should be.
   client_hwaddr = messagesplit[11]
   if dhcpopt == '350101': #DHCPDiscover
      print "Received: DHCPDISCOVER from:", client_hwaddr
      #craft DHCPOffer
      #DHCPOFFER creation:
      #options = \xcode \xlength \xdata
      try:
         lease=getlease(client_hwaddr)
      except:
         print 'ERROR: Could not obtain lease for', client_hwaddr
         return
      else:
         print 'Lease obtained:',lease, '('+client_hwaddr+')'
      data='\x02\x01\x06\x00'+binascii.unhexlify(messagesplit[4])+'\x00\x04' # OP+HTYPE+HLEN+HOPS+XID+SECS
      data+='\x80\x00'+'\x00'*4+socket.inet_aton(lease) # FLAGS+CIADDR+YIADDR
      data+=socket.inet_aton(serverhost)+'\x00'*4 # SIADDR+GIADDR
      data+=binascii.unhexlify(messagesplit[11])+'\x00'*10+'\x00'*192 # CHADDR
      data+='\x63\x82\x53\x63'+'\x35\x01\x02' # Magic Cookie+DHCP Option 53: DHCP Offer
      data+='\x01\x04'+socket.inet_aton(subnetmask) # DHCP Option 1 (netmask)+netmask
      data+='\x36\x04'+socket.inet_aton(serverhost) # DHCP Option 54 (DHCP server)+dhcp server
      data+='\x1c\x04'+socket.inet_aton(broadcast) # DHCP Option 28 (Broadcast address)+broadcast address
      if router != '':
         data+='\x03\x04'+socket.inet_aton(router) # DHCP Option 3 (Router)+router
      if dnsserver != '':
         data+='\x06\x04'+socket.inet_aton(dnsserver) # DHCP Option 6 (DNS Servers)+dns server
      data+='\x33\x04'+binascii.unhexlify(hex(leasetime)[2:].rjust(8,'0')) # DHCP Option 51 (Lease time)+lease time
      data+='\x42'+binascii.unhexlify(hex(len(tftpserver))[2:].rjust(2,'0'))+tftpserver # DHCP Option 66 (TFTP server name)+tftp server
      data+='\x43'+binascii.unhexlify(hex(len(pxefilename)+1)[2:].rjust(2,'0'))+pxefilename # DHCP Option 67 (Bootfile name)+boot filename
      data+='\x00\xff'
      print "Generated: DHCPOFFER"
   elif dhcpopt == '350103': #DHCPRequest
      print "Received: DHCPREQUEST from:", client_hwaddr
      #craft DHCPACK
      data='\x02\x01\x06\x00'+binascii.unhexlify(messagesplit[4])+'\x00\x00'+'\x00\x00'+'\x00'*4 # OP+HTYPE+HLEN+HOPS+XID+SECS+FLAGS+CIADDR
      data+=binascii.unhexlify(messagesplit[15][messagesplit[15].find('3204')+4:messagesplit[15].find('3204')+12]) # YIADDR
      data+=socket.inet_aton(serverhost)+'\x00'*4 # SIADDR+GIADDR
      data+=binascii.unhexlify(messagesplit[11])+'\x00'*10+'\x00'*192 # CHADDR
      data+='\x63\x82\x53\x63'+'\x35\x01\05' # Magic Cookie+DHCP Option 53: DHCP ACK
      data+='\x36\x04'+socket.inet_aton(serverhost) # DHCP Option 54 (DHCP server)+dhcp server
      data+='\x01\x04'+socket.inet_aton(subnetmask) # DHCP Option 1 (netmask)+netmask
      if router != '':
         data+='\x03\x04'+socket.inet_aton(serverhost) # DHCP Option 3 (Router)+router
      data+='\x33\x04'+binascii.unhexlify(hex(leasetime)[2:].rjust(8,'0')) # DHCP Option 51 (Lease time)+lease time
      data+='\x42'+binascii.unhexlify(hex(len(tftpserver))[2:].rjust(2,'0'))+tftpserver # DHCP Option 66 (TFTP server name)+tft server
      data+='\x43'+binascii.unhexlify(hex(len(pxefilename)+1)[2:].rjust(2,'0'))+pxefilename # DHCP Option 67 (Bootfile name)+boot filename
      data+='\x00\xff'
      print "Generated: DHCPACK"
   return data

while 1: #main loop
    try:
        message, address = s.recvfrom(8192)
        if not message.startswith('\x01') and not address[0] == '0.0.0.0':
           continue #only serve if a dhcp request
        data=reqparse(message) #handle request
        if data:
#           s.sendto(data,('<broadcast>',68)) #reply
           s.sendto(data,(broadcast,68)) #reply
           print "Sent reply"
        release() #update releases table
    except KeyboardInterrupt:
        exit()
#    except:
#        continue
