package org.owasp.proxy;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.List;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;

import javax.sql.DataSource;

import org.owasp.proxy.daemon.AutoGeneratingContextSelector;
import org.owasp.proxy.daemon.BufferedMessageInterceptor;
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
import org.owasp.proxy.dao.JdbcMessageDAO;
import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.httpclient.MutableResponseHeader;
import org.owasp.proxy.httpclient.RequestHeader;
import org.owasp.proxy.httpclient.SSLContextSelector;
import org.owasp.proxy.util.TextFormatter;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

public class Main {

	private static Logger logger = Logger.getLogger("org.owasp.proxy");

	private static void usage() {
		System.err
				.println("Usage: java -jar proxy.jar port [\"proxy instruction\"] [ <JDBC Driver> <JDBC URL> <username> <password> ]");
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

	private static DataSource createDataSource(String driver, String url,
			String username, String password) throws SQLException {
		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(driver);
		dataSource.setUrl(url);
		dataSource.setUsername(username);
		dataSource.setPassword(password);
		return dataSource;
	}

	public static void main(String[] args) throws Exception {
		logger.setUseParentHandlers(false);
		Handler ch = new ConsoleHandler();
		ch.setFormatter(new TextFormatter());
		logger.addHandler(ch);

		if (args == null
				|| (args.length != 1 && args.length != 2 && args.length != 5 && args.length != 6)) {
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
		if (args.length == 2 || args.length == 6) {
			proxy = args[1];
		}
		DataSource dataSource = null;
		if (args.length == 5) {
			dataSource = createDataSource(args[1], args[2], args[3], args[4]);
		} else if (args.length == 6) {
			dataSource = createDataSource(args[2], args[3], args[4], args[5]);
		}

		final ProxySelector ps = getProxySelector(proxy);

		DefaultHttpRequestHandler drh = new DefaultHttpRequestHandler() {
			@Override
			protected HttpClient createClient() {
				HttpClient client = super.createClient();
				client.setProxySelector(ps);
				return client;
			}
		};
		ServerGroup sg = new ServerGroup();
		sg.addServer(listen);
		drh.setServerGroup(sg);
		HttpRequestHandler rh = drh;
		rh = new LoggingHttpRequestHandler(rh);

		if (dataSource != null) {
			JdbcMessageDAO dao = new JdbcMessageDAO();
			dao.setDataSource(dataSource);
			dao.createTables();
			rh = new RecordingHttpRequestHandler(dao, rh, 1024 * 1024);
			rh = new ConversationServiceHttpRequestHandler("127.0.0.2", dao, rh);
		}
		BufferedMessageInterceptor bmi = new BufferedMessageInterceptor() {
			@Override
			public Action directResponse(RequestHeader request,
					MutableResponseHeader response) {
				return Action.BUFFER;
			}
		};
		rh = new BufferingHttpRequestHandler(rh, bmi, 10240, true);

		HttpProxyConnectionHandler hpch = new HttpProxyConnectionHandler(rh);
		SSLContextSelector cp = new AutoGeneratingContextSelector(".keystore",
				"JKS", "password".toCharArray());
		TargetedConnectionHandler tch = new SSLConnectionHandler(cp, true, hpch);
		tch = new LoopAvoidingTargetedConnectionHandler(sg, tch);
		hpch.setConnectHandler(tch);
		TargetedConnectionHandler socks = new SocksConnectionHandler(tch, true);
		Proxy p = new Proxy(listen, socks, null);
		p.setSocketTimeout(30000);
		p.start();

		System.out.println("Listener started on " + listen);
		System.out.println("Press Enter to terminate");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		p.stop();
		System.out.println("Terminated");
		System.exit(0);
	}
}
