package com.jInject;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.util.Date;

import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;

import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.packet.EthernetPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.TCPPacket;

public class Injector implements Runnable {
	Long seq;
	Long ack;
	Long tmp;
	NetworkInterface ifs;
	Integer dataLen;
	Integer srcPort;
	Integer dstPort;
	InetAddress dst;
	InetAddress src;
	JpcapSender sender;
	TCPPacket tcp;
	byte[] injectBuf;
	
	public  Injector(JpcapSender sender, TCPPacket tcpPack,byte[] injectBuf) {
		try {
		this.ifs=ifs;
		this.dst=tcpPack.src_ip;
		this.src=tcpPack.dst_ip;
		this.dstPort=tcpPack.src_port;
		this.srcPort=tcpPack.dst_port;
		this.seq=tcpPack.ack_num;
		this.ack=tcpPack.sequence;
		this.dataLen=tcpPack.data.length;
		this.injectBuf=injectBuf;
		tcp=tcpPack;
		this.sender = sender;
		} catch (Exception e) {
			e.printStackTrace();
		}
		
	}
	
	public void send(byte[] buf) { 
		ack=ack+dataLen;
		TCPPacket tcpReply = new TCPPacket(srcPort, dstPort, seq, ack, false, true, true, false, false, false, false, false, buf.length, 0);
		tcpReply.setIPv4Parameter(0,false,false,false,0,false,false,false,1460,1010101,100,IPPacket.IPPROTO_TCP,
					src,dst);
		tcpReply.data=buf;
			EthernetPacket getEther = (EthernetPacket) tcp.datalink;
			EthernetPacket ether=new EthernetPacket();
			ether.frametype=EthernetPacket.ETHERTYPE_IP;
			ether.src_mac= getEther.dst_mac;
			ether.dst_mac= getEther.src_mac;
			tcpReply.datalink=ether;
		sender.sendPacket(tcpReply);
		dataLen= buf.length;
		tmp=seq;
		seq=ack;
		ack=seq;

		
	}

	@Override
	public void run() { 
			try {
		// TODO Auto-generated method stub
		
		ByteInputStream fin = new ByteInputStream(injectBuf,injectBuf.length);
	
		Integer readCount = 0;
		byte[] buf = new byte[1460];
		readCount = fin.read(buf);
		while (readCount==1460) {
			send(buf);
			readCount = fin.read(buf);
		
		} 
		if (readCount!=0) {
			byte[] smallBuf = new byte[readCount];
			ByteArrayInputStream bytein = new ByteArrayInputStream(buf);
			bytein.read(smallBuf);
			send(smallBuf);
		}
		
			} catch (Exception e) {
				e.printStackTrace();
			}
	
		
	}

}
