import dpkt
import datetime
import socket

# pcap 파일을 바이너리 읽기 형태로 오픈
with open('homework1.pcap', 'rb') as f:
	pcap = dpkt.pcap.Reader(f)

	for timestamp, buf in pcap:
		eth = dpkt.ethernet.Ethernet(buf)
		ip = eth.data
		tcp = ip.data

		# 이더넷 타입인지 검사, 아니라면 패스
		if eth.type != dpkt.ethernet.ETH_TYPE_IP:
			continue    

		# TCP 프로토콜 패킷인지 검사, 아니라면 패스
		if ip.p != dpkt.ip.IP_PROTO_TCP:
			continue

		# 타임스탬프 출력
		print('Timestamp: ', timestamp)

		# 소스 Port, 목적지 Port 출력
		print('Src Port: ', tcp.sport)
		print('Dst Port: ', tcp.dport)

		# 소스 IP, 목적지 IP, 패킷 Length 출력
		print('IP: %s -> %s len=%d \n' % (socket.inet_ntoa(ip.src), socket.inet_ntoa(ip.dst), ip.len))