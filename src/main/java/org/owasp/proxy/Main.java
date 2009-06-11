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
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;

import org.owasp.httpclient.Client;
import org.owasp.httpclient.ReadOnlyRequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.SSLContextSelector;
import org.owasp.httpclient.dao.JdbcMessageDAO;
import org.owasp.proxy.daemon.AutoGeneratingContextSelector;
import org.owasp.proxy.daemon.BufferingHttpRequestHandler;
import org.owasp.proxy.daemon.ConversationServiceHttpRequestHandler;
import org.owasp.proxy.daemon.DefaultHttpRequestHandler;
import org.owasp.proxy.daemon.HttpProxyConnectionHandler;
import org.owasp.proxy.daemon.HttpRequestHandler;
import org.owasp.proxy.daemon.LoggingHttpRequestHandler;
import org.owasp.proxy.daemon.LoopAvoidingTargetedConnectionHandler;
import org.owasp.proxy.daemon.Proxy;
import org.owasp.proxy.daemon.RecordingHttpRequestHandler;
import org.owasp.proxy.daemon.SSLConnectionHandler;
import org.owasp.proxy.daemon.ServerGroup;
import org.owasp.proxy.daemon.SocksConnectionHandler;
import org.owasp.proxy.daemon.TargetedConnectionHandler;
import org.owasp.proxy.util.TextFormatter;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

public class Main {

	private static Logger logger = Logger.getLogger("org.owasp.proxy");

	private static void usage() {
		System.err
				.println("Usage: java -jar proxy.jar port [\"proxy instruction\"] [ Driver URL username password ]");
		System.err.println("Where \'proxy instruction\' might look like:");
		System.err
				.println("'DIRECT' or 'PROXY server:port' or 'SOCKS server:port'");
		System.err.println("and the JDBC connection details might look like:");
		System.err
				.println("org.h2.Driver jdbc:h2:mem:webscarab3;DB_CLOSE_DELAY=-1 sa \"\"");
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
				logger.info("Proxy connection to " + uri + " via " + sa
						+ " failed! " + ioe.getLocalizedMessage());
			}

			@Override
			public List<java.net.Proxy> select(URI uri) {
				return Arrays.asList(upstream);
			}
		};
		return ps;
	}

	public static void main(String[] args) throws Exception {
		logger.setUseParentHandlers(false);
		Handler ch = new ConsoleHandler();
		ch.setFormatter(new TextFormatter());
		logger.addHandler(ch);

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

		DefaultHttpRequestHandler drh = new DefaultHttpRequestHandler() {
			@Override
			protected Client createClient() {
				Client client = super.createClient();
				client.setProxySelector(ps);
				return client;
			}
		};
		ServerGroup sg = new ServerGroup();
		sg.addServer(listen);
		drh.setServerGroup(sg);
		HttpRequestHandler rh = drh;
		rh = new LoggingHttpRequestHandler(rh);

		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName("org.h2.Driver");
		dataSource.setUrl("jdbc:h2:mem:webscarab3;DB_CLOSE_DELAY=-1");
		// dataSource.setUsername("sa");
		// dataSource.setPassword("");
		JdbcMessageDAO dao = new JdbcMessageDAO();
		dao.setDataSource(dataSource);
		dao.setDataSource(dataSource);
		dao.createTables();
		rh = new RecordingHttpRequestHandler(dao, rh, 1024 * 1024);
		rh = new ConversationServiceHttpRequestHandler("127.0.0.2", dao, rh);
		rh = new BufferingHttpRequestHandler(rh, 10240, true) {
			@Override
			protected Action directResponse(ReadOnlyRequestHeader request,
					ResponseHeader response) {
				return Action.BUFFER;
			}
		};

		HttpProxyConnectionHandler hpch = new HttpProxyConnectionHandler(rh);
		// CertificateProvider cp = new DefaultCertificateProvider();
		SSLContextSelector cp = new AutoGeneratingContextSelector(
				".keystore", "JKS", "password".toCharArray());
		TargetedConnectionHandler tch = new SSLConnectionHandler(cp, true, hpch);
		tch = new LoopAvoidingTargetedConnectionHandler(sg, tch);
		hpch.setConnectHandler(tch);
		TargetedConnectionHandler socks = new SocksConnectionHandler(tch, true);
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
