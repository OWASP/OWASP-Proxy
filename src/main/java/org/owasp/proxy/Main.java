package org.owasp.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.owasp.proxy.daemon.CertificateProvider;
import org.owasp.proxy.daemon.DefaultCertificateProvider;
import org.owasp.proxy.daemon.Listener;
import org.owasp.proxy.daemon.LoggingProxyMonitor;
import org.owasp.proxy.daemon.ProxyMonitor;
import org.owasp.proxy.httpclient.DefaultHttpClientFactory;
import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.httpclient.HttpClientFactory;

public class Main {

	private static void usage() {
		System.err
				.println("Usage: java -jar proxy.jar port [\"proxy instruction\"]");
		System.err.println("Where \'proxy instruction\' might look like:");
		System.err
				.println("'DIRECT' or 'PROXY server:port' or 'SOCKS server:port'");
	}

	public static void main(String[] args) throws Exception {
		if (args == null || (args.length != 1 && args.length != 2)) {
			usage();
			return;
		}
		Listener.Configuration conf;
		InetSocketAddress listen;
		try {
			int port = Integer.parseInt(args[0]);
			listen = new InetSocketAddress("localhost", port);
			conf = new Listener.Configuration(listen);
		} catch (NumberFormatException nfe) {
			usage();
			return;
		}
		String proxy = "DIRECT";
		if (args.length == 3) {
			proxy = args[2];
		}

		final Proxy upstream;
		if ("DIRECT".equals(proxy)) {
			upstream = Proxy.NO_PROXY;
		} else {
			Proxy.Type type = null;
			if (proxy.startsWith("PROXY ")) {
				type = Proxy.Type.HTTP;
			} else if (proxy.startsWith("SOCKS ")) {
				type = Proxy.Type.SOCKS;
			} else
				throw new IllegalArgumentException("Unknown Proxy type: "
						+ proxy);
			proxy = proxy.substring(6); // "SOCKS " or "PROXY "
			int c = proxy.indexOf(':');
			if (c == -1)
				throw new IllegalArgumentException("Illegal proxy address: "
						+ proxy);
			InetSocketAddress addr = new InetSocketAddress(proxy
					.substring(0, c), Integer.parseInt(proxy.substring(c + 1)));
			upstream = new Proxy(type, addr);
		}
		final ProxySelector ps = new ProxySelector() {

			@Override
			public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
				System.err.println("Proxy connection failed! "
						+ ioe.getLocalizedMessage());
			}

			@Override
			public List<Proxy> select(URI uri) {
				return Arrays.asList(upstream);
			}
		};
		HttpClientFactory hcf = new DefaultHttpClientFactory() {

			@Override
			public HttpClient createHttpClient() {
				HttpClient client = super.createHttpClient();
				client.setProxySelector(ps);
				return client;
			}
		};
		ProxyMonitor lpm = new LoggingProxyMonitor();
		CertificateProvider cp = new DefaultCertificateProvider();

		conf.setCertificateProvider(cp);
		conf.setHttpClientFactory(hcf);
		conf.setProxyMonitor(lpm);

		Listener l = new Listener(conf);
		l.start();

		System.out.println("Listener started on " + conf.getListenerAddress());
		System.out.println("Press Enter to terminate");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		l.stop();
		System.out.println("Terminated");
	}
}
