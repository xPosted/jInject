package com.jInject;

import java.io.BufferedInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Scanner;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.sound.sampled.AudioFormat.Encoding;

import com.sun.org.apache.bcel.internal.generic.INSTANCEOF;
import com.sun.org.apache.xerces.internal.impl.io.UTF8Reader;
import com.sun.xml.internal.messaging.saaj.util.ByteInputStream;

import jpcap.JpcapSender;
import jpcap.NetworkInterface;
import jpcap.PacketReceiver;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;

public class Sniffer implements PacketReceiver ,Runnable {
	SimpleDateFormat sdf = new SimpleDateFormat("hh:mm:ss");
	boolean log=false;;
	
	String urlPattern = null;
	String noUrlPattern = null;
	Pattern p=null;
	Pattern nop=null;
	Matcher m;
	ArrayList<String> lines = new ArrayList<String>();
	NetworkInterface ifs = null;
	String path;
	ExecutorService exec = Executors.newCachedThreadPool();
	byte[] injectBuf;
	ByteInputStream byteIn;
	Scanner scan;
	Packet arg0; 
	JpcapSender sender;
	
	public Sniffer() {
		
		
		
	}

	@Override
	public void receivePacket(Packet arg0) {
		try {
			Sniffer sn = new Sniffer();
				sn.setLog(log);
				sn.setPath(path);
				sn.setUrl(urlPattern);
				sn.setArg0(arg0);
				sn.setIfs(ifs);
				sn.setSender(sender);
				sn.setNoUrlPattern(noUrlPattern);
				
				exec.submit(sn);
		} catch (Exception e) {
			e.printStackTrace();
		}

		
	}
	private void print(ArrayList<String> lns){
		for (String line : lns) {
			System.out.println("\t"+line);
		}
		
	}
	
	private boolean matcher(String in) {
		m = p.matcher(in);
		if (m.matches()) {
			if (!nomatcher(in)) {
				return true;
			}
		}
			return false;
	//	return m.matches();
	}
	
	private boolean nomatcher(String in) {
		if (noUrlPattern==null) return false;
		return nop.matcher(in).matches();
	
	}



	public synchronized String getUrl() {
		return urlPattern;
	}


	public synchronized void setUrl(String url) {
		p = Pattern.compile(url);
		this.urlPattern = url;
	}

	public synchronized NetworkInterface getIfs() {
		return ifs;
	}
	public synchronized void setIfs(NetworkInterface ifs) {
		this.ifs = ifs;
	}
	public synchronized String getPath() {
		return path;
	}
	public synchronized void setPath(String path) {
		this.path = path;
		File f = new File(path);
		injectBuf = new byte[(int)f.length()];
		try {
			FileInputStream fin = new FileInputStream(f);
			Integer count =  fin.read(injectBuf);
			if (injectBuf.length!=count) {
				System.out.println("\t\t inject file read error");
			}
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	public synchronized String getNoUrlPattern() {
		return noUrlPattern;
	}

	public synchronized void setNoUrlPattern(String noUrlPattern) {
		if (noUrlPattern!=null)
			nop = Pattern.compile(noUrlPattern);
		this.noUrlPattern = noUrlPattern;
	}

	public synchronized boolean isLog() {
		return log;
	}

	public synchronized void setLog(boolean log) {
		this.log = log;
	}

	@Override
	public void run() {
		TCPPacket tcpPack = (TCPPacket) arg0;
		byte[] buf = tcpPack.data;
		
		byteIn = new ByteInputStream(buf, buf.length);
		scan = new Scanner(byteIn);
		String resLine="";
		lines.clear();
		boolean match = false;
		while (scan.hasNext()) {
			String line = scan.nextLine();
			lines.add(line);
			resLine=resLine+line;
			
			
		}
		
		if (matcher(resLine)) {
			
			Injector inject = new Injector(sender, tcpPack,injectBuf);
			inject.run();
		//	exec.execute(inject);
			match=true;
			if (log) {
				System.out.print("\n\n "+sdf.format(new Date()));
				print(lines);
			}
			
		}	
		
	}

	public synchronized Packet getArg0() {
		return arg0;
	}

	public synchronized void setArg0(Packet arg0) {
		this.arg0 = arg0;
	}

	public synchronized JpcapSender getSender() {
		return sender;
	}

	public synchronized void setSender(JpcapSender sender) {
		this.sender = sender;
	}
	

}
