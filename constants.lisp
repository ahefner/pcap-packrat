
(in-package :packrat)

(defconstant +IPV4+      #x0800        "Internet IP (IPv4)")
(defconstant +X25+      #x0805)
(defconstant +ARP+      #x0806         "Address Resolution Protocol")
(defconstant +FR_ARP+      #x0808      "Frame Relay ARP")
(defconstant +BPQ+      #x08FF         "G88BPQ AX.25 Ethernet Packet")
(defconstant +DEC+      #x6000         "DEC Assigned Proto")
(defconstant +DNA_DL+      #x6001      "DEC DNA Dump/Load")
(defconstant +DNA_RC+      #x6002      "DEC DNA Remote Console")
(defconstant +DNA_RT+      #x6003      "DEC DNA Routing")
(defconstant +LAT+      #x6004         "DEC LAT")
(defconstant +DIAG+      #x6005        "DEC Diagnostics")
(defconstant +CUST+      #x6006        "DEC Customer Use")
(defconstant +SCA+      #x6007         "DEC Systems Comms Arch")
(defconstant +TEB+      #x6558         "Trans Ether Bridging")
(defconstant +RAW_FR+      #x6559      "Raw Frame Relay")
(defconstant +AARP+      #x80F3        "Appletalk AARP")
(defconstant +ATALK+      #x809B       "Appletalk")
(defconstant +802_1Q+      #x8100      "802.1Q Virtual LAN Tagged Frame")
(defconstant +IPX+      #x8137         "Novell IPX")
(defconstant +NETBEUI+      #x8191)
(defconstant +IPV6+      #x86DD        "IP version 6")
(defconstant +PPP+      #x880B         "Point-to-Point protocol")
(defconstant +ATMMPOA+      #x884C     "MultiProtocol over ATM")
(defconstant +PPP_DISC+      #x8863    "PPPoE discovery messages")
(defconstant +PPP_SES+      #x8864     "PPPoE session messages")
(defconstant +ATMFATE+      #x8884     "Frame-based ATM Transport over Ethernet")
(defconstant +EAP-802.1+    #x888E     "IEEE 802.1x EAP over LAN")
(defconstant +LOOP+      #x9000        "Loop proto")


(defun etherproto-name (number)
  (case number
    (#x0800 "Internet IP (IPv4)")
    (#x0805 "X25")
    (#x0806 "Address Resolution Protocol")
    (#x0808 "Frame Relay ARP")
    (#x08FF "G88BPQ AX.25 Ethernet Packet")
    (#x6000 "DEC Assigned Proto")
    (#x6001 "DEC DNA Dump/Load")
    (#x6002 "DEC DNA Remote Console")
    (#x6003 "DEC DNA Routing")
    (#x6004 "DEC LAT")
    (#x6005 "DEC Diagnostics")
    (#x6006 "DEC Customer Use")
    (#x6007 "DEC Systems Comms Arch")
    (#x6558 "Trans Ether Bridging")
    (#x6559 "Raw Frame Relay")
    (#x80F3 "Appletalk AARP")
    (#x809B "Appletalk")
    (#x8100 "802.1Q Virtual LAN Tagged Frame")
    (#x8137 "Novell IPX")
    (#x8191 "NETBEUI")
    (#x86DD "IP version 6")
    (#x880B "Point-to-Point protocol")
    (#x884C "MultiProtocol over ATM")
    (#x8863 "PPPoE discovery messages")
    (#x8864 "PPPoE session messages")
    (#x8884 "Frame-based ATM Transport over Ethernet")
    (#x888E "IEEE 802.1x EAP over LAN")
    (#x9000 "Loop proto")))

(defun ipproto-name (number)
  (case number
    (0	"HOPOPT, IPv6 Hop-by-Hop Option")
    (1	"ICMP, Internet Control Message Protocol")
    (2	"IGAP / IGMP / RGMP")
    (3	"GGP, Gateway to Gateway Protocol")
    (4	"IP in IP encapsulation")
    (5	"ST, Internet Stream Protocol")
    (6	"TCP, Transmission Control Protocol")
    (7	"UCL, CBT")
    (8	"EGP, Exterior Gateway Protocol")
    (9	"IGRP, Interior Gateway Routing Protocol")
    (10	"BBN RCC Monitoring")
    (11	"NVP, Network Voice Protocol")
    (12	"PUP")
    (13	"ARGUS")
    (14	"EMCON, Emission Control Protocol")
    (15	"XNET, Cross Net Debugger")
    (16	"Chaos")
    (17	"UDP, User Datagram Protocol")
    (18	"TMux, Transport Multiplexing Protocol")
    (19	"DCN Measurement Subsystems")
    (20	"HMP, Host Monitoring Protocol")
    (21	"Packet Radio Measurement")
    (22	"XEROX NS IDP")
    (23	"Trunk-1")
    (24	"Trunk-2")
    (25	"Leaf-1")
    (26	"Leaf-2")
    (27	"RDP, Reliable Data Protocol")
    (28	"IRTP, Internet Reliable Transaction Protocol")
    (29	"ISO Transport Protocol Class 4")
    (30	"NETBLT, Network Block Transfer")
    (31	"MFE Network Services Protocol")
    (32	"MERIT Internodal Protocol")
    (33	"DCCP, Datagram Congestion Control Protocol")
    (34	"Third Party Connect Protocol")
    (35	"IDPR, Inter-Domain Policy Routing Protocol")
    (36	"XTP, Xpress Transfer Protocol")
    (37	"Datagram Delivery Protocol")
    (38	"IDPR, Control Message Transport Protocol")
    (39	"TP++ Transport Protocol")
    (40	"IL Transport Protocol")
    (41	"IPv6 over IPv4")
    (42	"SDRP, Source Demand Routing Protocol")
    (43	"IPv6 Routing header")
    (44	"IPv6 Fragment header")
    (45	"IDRP, Inter-Domain Routing Protocol")
    (46	"RSVP, Reservation Protocol")
    (47	"GRE, General Routing Encapsulation")
    (48	"DSR, Dynamic Source Routing Protocol")
    (49	"BNA")
    (50	"ESP, Encapsulating Security Payload")
    (51	"AH, Authentication Header")
    (52	"I-NLSP, Integrated Net Layer Security TUBA")
    (53	"SWIPE, IP with Encryption")
    (54	"NARP, NBMA Address Resolution Protocol")
    (55	"Minimal Encapsulation Protocol")
    (56	"TLSP, Transport Layer Security Protocol using Kryptonet key management")
    (57	"SKIP")
    (58	"ICMPv6, Internet Control Message Protocol for IPv6")
    (59	"IPv6 No Next Header")
    (60	"IPv6 Destination Options")
    (61	"Any host internal protocol")
    (62	"CFTP")
    (63	"Any local network")
    (64 "SATNET and Backroom EXPAK")
    (65 "Kryptolan")
    (66 "MIT Remote Virtual Disk Protocol")
    (67 "Internet Pluribus Packet Core")
    (68 "Any distributed file system")
    (69 "SATNET Monitoring")
    (70 "VISA Protocol")
    (71 "Internet Packet Core Utility")
    (72 "Computer Protocol Network Executive")
    (73 "Computer Protocol Heart Beat")
    (74 "Wang Span Network")
    (75 "Packet Video Protocol")
    (76 "Backroom SATNET Monitoring")
    (77 "SUN ND PROTOCOL-Temporary")
    (78	"WIDEBAND Monitoring")
    (79	"WIDEBAND EXPAK")
    (80	"ISO-IP")
    (81	"VMTP, Versatile Message Transaction Protocol")
    (82	"SECURE-VMTP")
    (83	"VINES")
    (84	"TTP")
    (85	"NSFNET-IGP")
    (86 "Dissimilar Gateway Protocol")
    (87 "TCF")
    (88 "EIGRP")
    (89	"OSPF / MOSPF")
    (90	"Sprite RPC Protocol")
    (91	"Locus Address Resolution Protocol")
    (92	"MTP, Multicast Transport Protocol")
    (93	"AX.25")
    (94	"IP-within-IP Encapsulation Protocol")
    (95 "Mobile Internetworking Control Protocol")
    (96 "Semaphore Communications Sec. Pro")
    (97 "EtherIP")
    (98 "Encapsulation Header")
    (99 "Any private encryption scheme")
    (100 "GMTP")
    (101 "IFMP, Ipsilon Flow Management Protocol")
    (102 "PNNI over IP")
    (103 "PIM, Protocol Independent Multicast")
    (104 "ARIS")
    (105 "SCPS")
    (106 "QNX")
    (107 "Active Networks")
    (108 "IPPCP, IP Payload Compression Protocol")
    (109 "SNP, Sitara Networks Protocol")
    (110 "Compaq Peer Protocol")
    (111 "IPX in IP")
    (112 "VRRP, Virtual Router Redundancy Protocol")
    (113 "PGM, Pragmatic General Multicast")
    (114 "any 0-hop protocol")
    (115 "L2TP, Level 2 Tunneling Protocol")
    (116 "DDX, D-II Data Exchange")
    (117 "IATP, Interactive Agent Transfer Protocol")
    (118 "ST, Schedule Transfer")
    (119 "SRP, SpectraLink Radio Protocol")
    (120 "UTI")
    (121 "SMP, Simple Message Protocol")
    (122 "SM")
    (123 "PTP, Performance Transparency Protocol")
    (124 "ISIS over IPv4")
    (125 "FIRE")
    (126 "CRTP, Combat Radio Transport Protocol")
    (127 "CRUDP, Combat Radio User Datagram")
    (128 "SSCOPMCE")
    (129 "IPLT")
    (130 "SPS, Secure Packet Shield")
    (131 "PIPE, Private IP Encapsulation within IP")
    (132 "SCTP, Stream Control Transmission Protocol")
    (133 "Fibre Channel")
    (134 "RSVP-E2E-IGNORE")
    (135 "Mobility Header")
    (136 "UDP-Lite, Lightweight User Datagram Protocol")
    (137 "MPLS in IP")
    (138 "MANET Protocols")
    (139 "HIP, Host Identity Protocol")))