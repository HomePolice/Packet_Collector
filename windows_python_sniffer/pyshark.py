import pyshark
# 인터페이스 en0에 대한 라이브 패킷캡처 결과를 cap에 저장
cap = pyshark.LiveCapture(interface='en0')
# 10개의 패킷만 캡처
cap.sniff(packet_count=10)

# 캡처된 패킷 정보 출력
for pkt in cap:
	print(pkt)