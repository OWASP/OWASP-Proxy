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
import org.owasp.proxy.daemon.Proxy;
import org.owasp.proxy.daemon.Proxy.SOCKS;
import org.owasp.proxy.daemon.SSLProxy.SSL;
import org.owasp.proxy.examples.LoggingHttpProxy;

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

		Proxy p = new LoggingHttpProxy(listen, null, SOCKS.AUTO, SSL.AUTO) {
			/*
			 * (non-Javadoc)
			 * 
			 * @see org.owasp.proxy.daemon.DefaultHttpProxy#createHttpClient()
			 */
			@Override
			protected Client createHttpClient() {
				Client client = super.createHttpClient();
				client.setProxySelector(ps);
				return client;
			}
		};
		p.start();

		System.out.println("Listener started on " + listen);
		System.out.println("Press Enter to terminate");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		p.stop();
		System.out.println("Terminated");
	}
}
