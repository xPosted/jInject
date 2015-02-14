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
	Integer byteAtTime=1460;  //we can not send at once more data than ethernet packet len
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
	public void sendACK() {
		Long tmp_ack=ack+dataLen;
		Long tmp_seq = seq; 
		
		TCPPacket tcpReply = new TCPPacket(srcPort, dstPort, tmp_seq, tmp_ack, false, true, false, false, false, false, false, false, tcp.window, 0);
		tcpReply.setIPv4Parameter(0,false,false,false,0,false,false,false,0,1010101,100,IPPacket.IPPROTO_TCP,
					src,dst);
		tcpReply.data= new byte[0];
			EthernetPacket getEther = (EthernetPacket) tcp.datalink;
			EthernetPacket ether=new EthernetPacket();
			ether.frametype=EthernetPacket.ETHERTYPE_IP;
			ether.src_mac= getEther.dst_mac;
			ether.dst_mac= getEther.src_mac;
			tcpReply.datalink=ether;
		sender.sendPacket(tcpReply);
		
	}
	
	public void sendRST() {
		TCPPacket tcpReply = new TCPPacket(dstPort, srcPort, ack+tcp.data.length, seq, false, true, true, true, false, false, false, false, tcp.window, 0);
		tcpReply.setIPv4Parameter(0,false,false,false,0,false,false,false,0,1010101,100,IPPacket.IPPROTO_TCP,
					dst,src);
		tcpReply.data="fuck_off".getBytes();
			EthernetPacket getEther = (EthernetPacket) tcp.datalink;
			EthernetPacket ether=new EthernetPacket();
			ether.frametype=EthernetPacket.ETHERTYPE_IP;
			ether.src_mac= getEther.src_mac;
			ether.dst_mac= getEther.dst_mac;
			tcpReply.datalink=ether;
		sender.sendPacket(tcpReply);
	}
	
	public void send(byte[] buf,boolean last) { 
		
		TCPPacket tcpReply = new TCPPacket(srcPort, dstPort, seq, ack, false, true, last, false, false, last, false, false, tcp.window, 0); 
		tcpReply.setIPv4Parameter(0,false,false,false,0,false,false,false,0,1010101,100,IPPacket.IPPROTO_TCP,
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
		seq=seq+dataLen;

		
	}

	@Override
	public void run() { 
			try {
		// TODO Auto-generated method stub
	//	sendRST();
	//	sendACK();
		ByteInputStream fin = new ByteInputStream(injectBuf,injectBuf.length);
		boolean last=false;
		Integer readCount = 0;
		byte[] buf = new byte[byteAtTime];
		readCount = fin.read(buf);
		ack=ack+dataLen;
		while (readCount.equals(byteAtTime)) {
			if (fin.available()==0) last = true; 
			send(buf,last);
			readCount = fin.read(buf);
		
		} 
		if (readCount!=0) {
			byte[] smallBuf = new byte[readCount];
			ByteArrayInputStream bytein = new ByteArrayInputStream(buf);
			bytein.read(smallBuf);
			send(smallBuf,true);
		}
		
			} catch (Exception e) {
				e.printStackTrace();
			}
	
		
	}

}
