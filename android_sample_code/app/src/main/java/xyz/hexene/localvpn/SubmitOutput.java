package xyz.hexene.localvpn;

import android.util.Log;

import java.io.IOException;
import java.net.InetAddress;
import java.nio.ByteBuffer;
import java.util.Random;
import java.util.concurrent.ConcurrentLinkedQueue;

import xyz.hexene.localvpn.Packet.TCPHeader;

// 패킷 수집을 위해 새로 작성한 클래스
// submit큐를 지속적으로 확인하여 데이터를 수집한다.
public class SubmitOutput implements Runnable {
    private static final String TAG = SubmitOutput.class.getSimpleName();

    private LocalVPNService vpnService;
    private ConcurrentLinkedQueue<Packet> inputQueue;

    private Random random = new Random();

    public SubmitOutput(ConcurrentLinkedQueue<Packet> inputQueue, LocalVPNService vpnService) {
        this.inputQueue = inputQueue;
        this.vpnService = vpnService;
    }

    @Override
    public void run() {
        Log.i(TAG, "Started");
        try {
            Thread currentThread = Thread.currentThread();
            while (true) {
                Packet currentPacket;
                // TODO: Block when not connected
                // submit큐를 지속적으로 확인하는 부분
                // 없으면 10초씩 sleep한다.
                do {
                    currentPacket = inputQueue.poll();
                    if (currentPacket != null)
                        break;
                    Thread.sleep(10);
                } while (!currentThread.isInterrupted());

                if (currentThread.isInterrupted())
                    break;

                String ip;
                int destinationPort;
                int sourcePort;
                InetAddress destinationAddress;

                // 큐에서 데이터를 꺼내오면 tcp, udp로 분류하고 패킷내부에서 필요한 정보 (source IP/port, dest IP/port, protocol)을 꺼내 가공하여 출력한다.
                // 나중에 s3 또는 neo4j로 전송하는 부분 작성이 필요
                if (currentPacket.isTCP()) {
                    ByteBuffer payloadBuffer = currentPacket.backingBuffer;
                    currentPacket.backingBuffer = null;
                    ByteBuffer responseBuffer = ByteBufferPool.acquire();

                    destinationAddress = currentPacket.ip4Header.destinationAddress;

                    TCPHeader tcpHeader = currentPacket.tcpHeader;
                    destinationPort = tcpHeader.destinationPort;
                    sourcePort = tcpHeader.sourcePort;

                    ip = destinationAddress.getHostAddress();

                    System.out.println(ip + " " + destinationPort + " " + sourcePort);
                } else if (currentPacket.isUDP()) {
                    destinationAddress = currentPacket.ip4Header.destinationAddress;
                    destinationPort = currentPacket.udpHeader.destinationPort;
                    sourcePort = currentPacket.udpHeader.sourcePort;

                    ip = destinationAddress.getHostAddress();

                    System.out.println(ip + " " + destinationPort + " " + sourcePort);
                } else {

                }
            }
        }
        catch (InterruptedException e)
        {
            Log.i(TAG, "Stopping");
        }
    }
}