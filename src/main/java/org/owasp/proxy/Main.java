package org.owasp.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.util.Arrays;
import java.util.List;

import org.owasp.httpclient.Client;
import org.owasp.proxy.daemon.DefaultCertificateProvider;
import org.owasp.proxy.daemon.DefaultHttpRequestHandler;
import org.owasp.proxy.daemon.HttpProxyConnectionHandler;
import org.owasp.proxy.daemon.HttpRequestHandler;
import org.owasp.proxy.daemon.LoggingHttpRequestHandler;
import org.owasp.proxy.daemon.Proxy;
import org.owasp.proxy.daemon.SSLConnectionHandler;
import org.owasp.proxy.daemon.SocksConnectionHandler;
import org.owasp.proxy.daemon.TargetedConnectionHandler;

public class Main {

	private static void usage() {
		System.err
				.println("Usage: java -jar proxy.jar port [\"proxy instruction\"]");
		System.err.println("Where \'proxy instruction\' might look like:");
		System.err
				.println("'DIRECT' or 'PROXY server:port' or 'SOCKS server:port'");
	}

	private static ProxySelector getProxySelector(String proxy) {
		final java.net.Proxy upstream;
		if ("DIRECT".equals(proxy)) {
			upstream = java.net.Proxy.NO_PROXY;
		} else {
			java.net.Proxy.Type type = null;
			if (proxy.startsWith("PROXY ")) {
				type = java.net.Proxy.Type.HTTP;
			} else if (proxy.startsWith("SOCKS ")) {
				type = java.net.Proxy.Type.SOCKS;
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
			upstream = new java.net.Proxy(type, addr);
		}
		ProxySelector ps = new ProxySelector() {

			@Override
			public void connectFailed(URI uri, SocketAddress sa, IOException ioe) {
				System.err.println("Proxy connection failed! "
						+ ioe.getLocalizedMessage());
			}

			@Override
			public List<java.net.Proxy> select(URI uri) {
				return Arrays.asList(upstream);
			}
		};
		return ps;
	}

	public static void main(String[] args) throws Exception {
		if (args == null || (args.length != 1 && args.length != 2)) {
			usage();
			return;
		}
		InetSocketAddress listen;
		try {
			int port = Integer.parseInt(args[0]);
			listen = new InetSocketAddress("localhost", port);
		} catch (NumberFormatException nfe) {
			usage();
			return;
		}
		String proxy = "DIRECT";
		if (args.length == 3) {
			proxy = args[2];
		}

		final ProxySelector ps = getProxySelector(proxy);

		HttpRequestHandler rh = new DefaultHttpRequestHandler() {
			@Override
			protected Client createClient() {
				Client client = super.createClient();
				client.setProxySelector(ps);
				return client;
			}
		};
		rh = new LoggingHttpRequestHandler(rh);
		HttpProxyConnectionHandler hpch = new HttpProxyConnectionHandler(rh);
		SSLConnectionHandler sch = new SSLConnectionHandler(
				new DefaultCertificateProvider(), true, hpch);
		hpch.setConnectHandler(sch);
		TargetedConnectionHandler socks = new SocksConnectionHandler(sch, true);
		Proxy p = new Proxy(listen, socks, null);
		p.start();

		System.out.println("Listener started on " + listen);
		System.out.println("Press Enter to terminate");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		p.stop();
		System.out.println("Terminated");
		System.exit(0);
	}
}
