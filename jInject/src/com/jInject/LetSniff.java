package com.jInject;

import java.io.IOException;
import java.text.SimpleDateFormat;
import java.util.Date;

import jpcap.JpcapCaptor;
import jpcap.JpcapSender;
import jpcap.NetworkInterface;

public class LetSniff {
	static String ifs = null;
	static String fileToIn = null;
	static String pattern = null;
	static String exp = null;
	static String noPattern = null;
	static boolean log = false;
	static JpcapSender sender;
	
	public static void main(String[] args) throws IOException {
		
		
		
		 if (!caseing(args)) return;
		
		
		NetworkInterface ifses[] = JpcapCaptor.getDeviceList();
		Integer i=0;
		for (NetworkInterface intrf : ifses) {
			if (intrf.name.equals(ifs))	{
				SimpleDateFormat sdf = new SimpleDateFormat("mm-dd-yyyy hh:mm:ss");
				System.out.println(sdf.format(new Date())+"  Start sniffing on  "+intrf.name+" "+ intrf.datalink_name);
				System.out.println("\tUsing pattern: "+pattern);
				System.out.println("\tFile to inject: "+fileToIn);
				System.out.println("\tExcept pattern: "+noPattern);
				System.out.println("\tPcap expression: "+exp);
				System.out.println("====================================================\n\n");
				
				
				JpcapCaptor captor =  JpcapCaptor.openDevice(intrf, 16384, true, 0);
				sender = JpcapSender.openDevice(intrf);
				captor.setFilter(exp, true);
				Sniffer sniff = new Sniffer();
				sniff.setUrl(pattern);
				sniff.setIfs(intrf);
				sniff.setPath(fileToIn);
				sniff.setSender(sender);
				sniff.setNoUrlPattern(noPattern);
				sniff.setLog(log);
				captor.loopPacket(-1, sniff);
			}
			
			
			
		}
		
		

	}
	
	public static  boolean  caseing(String[] arg) { 
		Integer i=0;
		if (arg.length==0) {showHelp(); return false;}
		while (i<arg.length) {
			 if (arg[i].equals("-i")) {ifs=arg[i+1]; i=i+2; continue;} 
			
			 if (arg[i].equals("-f")) {fileToIn=arg[i+1]; i=i+2; continue;}
			 
			 if (arg[i].equals("-p")) {pattern=arg[i+1]; i=i+2; continue;}
			 
			 if (arg[i].equals("-e")) {exp=arg[i+1]; i=i+2; continue;}
			 
			 if (arg[i].equals("-n")) {noPattern=arg[i+1]; i=i+2; continue;}
			 
			 if (arg[i].equals("-l")) {log=true; i=i+1; continue;}
			 
			 System.out.println("'"+arg[i]+"' unknown argument");  
			 return false;
			
			
			
		}
		if (ifs==null) {showHelp(); return false;}
		if (fileToIn==null) {showHelp(); return false;}
		if (pattern==null) {showHelp(); return false;}
		if (exp==null) {showHelp(); return false;}
		
		return true;
		
			
	}
	
	public static void showHelp() {
		System.out.println("Using: java -jar TCPsniff.jar -i [ifs] -f [path_to_file] -p [pattern] -e [pcap expression] -n [except pattern] -l");
		System.out.println("\t -i [ifs] : Listen on interface named 'ifs'");
		System.out.println("\t -f [path_to_file] : When packet meet the pattern this file will be injected");
		System.out.println("\t -p [pattern] : Regular expression");
		System.out.println("\t -e ['pcap expression'] : pcap packet filter");
		System.out.println("\t -n ['Except pattern'] : Packets that well meet this pattern will be ignored (optional)");
		System.out.println("\t -l : Verbose mode (optional)");
		
		
	}
	
	

}
