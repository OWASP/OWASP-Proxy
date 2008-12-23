package org.owasp.proxy;

import java.io.BufferedReader;
import java.io.InputStreamReader;

import org.owasp.proxy.daemon.CertificateProvider;
import org.owasp.proxy.daemon.DefaultCertificateProvider;
import org.owasp.proxy.daemon.Listener;
import org.owasp.proxy.daemon.LoggingProxyMonitor;
import org.owasp.proxy.daemon.ProxyMonitor;
import org.owasp.proxy.daemon.SocksListener;

public class Main {

	private static void usage() {
		System.err.println("Usage: java -jar proxy.jar httpPort socksPort");
	}
	
	public static void main(String[] args) {
		if (args == null || args.length != 2) {
			usage();
			return;
		}
		int httpPort, socksPort;
		try {
			httpPort = Integer.parseInt(args[0]);
			socksPort = Integer.parseInt(args[1]);
		} catch (NumberFormatException nfe) {
			usage();
			return;
		}
		try {
			ProxyMonitor lpm = new LoggingProxyMonitor();
			CertificateProvider cp = new DefaultCertificateProvider();

			Listener l = new Listener(httpPort);
			l.setProxyMonitor(lpm);
			l.setCertificateProvider(cp);
			l.start();

			Listener sl = new SocksListener(socksPort);
			sl.setProxyMonitor(lpm);
			sl.setCertificateProvider(cp);
			sl.start();

			System.out.println("Http listener started on " + httpPort + ", SOCKS listener started on " + socksPort);
			System.out.println("Press Enter to terminate");
			new BufferedReader(new InputStreamReader(System.in)).readLine();
			sl.stop();
			l.stop();
			System.out.println("Terminated");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}
}
