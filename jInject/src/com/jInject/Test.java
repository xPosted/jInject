package com.jInject;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.regex.Pattern;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;


public class Test {

	public static void main(String[] args) throws Exception {
		NetworkInterface[] ifs =  JpcapCaptor.getDeviceList();
		JpcapSender sender = JpcapSender.openDevice(ifs[0]);
		byte[] buf = new byte[1460];
		TCPPacket tcpReply = new TCPPacket(8000, 8001, 666, 777, false, true, false, false, false, false, false, false, 4096, 0);
		tcpReply.setIPv4Parameter(0,false,false,false,14,false,false,false,0,1,10,IPPacket.IPPROTO_TCP,
					InetAddress.getByName("172.16.0.77"),InetAddress.getByName("172.16.0.71"));
		tcpReply.data=buf;
			tcpReply.sequence=100;
		EthernetPacket ether=new EthernetPacket();
		ether.frametype=EthernetPacket.ETHERTYPE_IP;
		
		ether.src_mac=new byte[]{(byte)0,(byte)1,(byte)2,(byte)3,(byte)4,(byte)5};
		ether.dst_mac=new byte[]{(byte)0,(byte)6,(byte)7,(byte)8,(byte)9,(byte)10};

			tcpReply.datalink=ether;
		for (Integer i=0;i<2;i++)
		sender.sendPacket(tcpReply);
		
		

	}

}
