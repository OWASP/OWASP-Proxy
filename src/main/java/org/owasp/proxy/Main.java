/*
 * This file is part of the OWASP Proxy, a free intercepting proxy library.
 * Copyright (C) 2008-2010 Rogan Dawes <rogan@dawes.za.net>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to:
 * The Free Software Foundation, Inc., 
 * 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA
 *
 */

package org.owasp.proxy;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.Authenticator;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.PasswordAuthentication;
import java.net.ProxySelector;
import java.net.SocketAddress;
import java.net.URI;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.sql.SQLException;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.logging.ConsoleHandler;
import java.util.logging.Handler;
import java.util.logging.Logger;

import javax.net.ssl.X509KeyManager;
import javax.security.auth.x500.X500Principal;
import javax.sql.DataSource;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.GnuParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.OptionBuilder;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.owasp.proxy.ajp.AJPProperties;
import org.owasp.proxy.ajp.DefaultAJPRequestHandler;
import org.owasp.proxy.daemon.LoopAvoidingTargetedConnectionHandler;
import org.owasp.proxy.daemon.Proxy;
import org.owasp.proxy.daemon.ServerGroup;
import org.owasp.proxy.daemon.TargetedConnectionHandler;
import org.owasp.proxy.http.MessageFormatException;
import org.owasp.proxy.http.MutableRequestHeader;
import org.owasp.proxy.http.MutableResponseHeader;
import org.owasp.proxy.http.RequestHeader;
import org.owasp.proxy.http.StreamingRequest;
import org.owasp.proxy.http.StreamingResponse;
import org.owasp.proxy.http.client.HttpClient;
import org.owasp.proxy.http.dao.JdbcMessageDAO;
import org.owasp.proxy.http.server.AuthenticatingHttpRequestHandler;
import org.owasp.proxy.http.server.BufferedMessageInterceptor;
import org.owasp.proxy.http.server.BufferingHttpRequestHandler;
import org.owasp.proxy.http.server.ConversationServiceHttpRequestHandler;
import org.owasp.proxy.http.server.DefaultHttpRequestHandler;
import org.owasp.proxy.http.server.HttpProxyConnectionHandler;
import org.owasp.proxy.http.server.HttpRequestHandler;
import org.owasp.proxy.http.server.LoggingHttpRequestHandler;
import org.owasp.proxy.http.server.RecordingHttpRequestHandler;
import org.owasp.proxy.socks.SocksConnectionHandler;
import org.owasp.proxy.ssl.AutoGeneratingContextSelector;
import org.owasp.proxy.ssl.DefaultClientContextSelector;
import org.owasp.proxy.ssl.KeystoreUtils;
import org.owasp.proxy.ssl.SSLConnectionHandler;
import org.owasp.proxy.ssl.SSLContextSelector;
import org.owasp.proxy.tcp.ConnectConnectionHandler;
import org.owasp.proxy.util.TextFormatter;
import org.springframework.jdbc.datasource.DriverManagerDataSource;

public class Main {

	private static Logger logger = Logger.getLogger("org.owasp.proxy");

	private static class Configuration {
		private static final String OPT_AUTHUSER = "authUser";
		private static final String OPT_AUTHPASSWORD = "authPassword";
		private static final String OPT_AJPSERVER = "ajpServer";
		private static final String OPT_AJPHOST = "ajpHost";
		private static final String OPT_AJPUSER = "ajpUser";
		private static final String OPT_AJPCLIENTADDRESS = "ajpClientAddress";
		private static final String OPT_PKCS11SLOTLOCATION = "pkcs11SlotLocation";
		private static final String OPT_KEYSTOREPASSWORD = "keyStorePassword";
		private static final String OPT_KEYSTOREALIAS = "keyStoreAlias";
		private static final String OPT_KEYSTORELOCATION = "keyStoreLocation";
		private static final String OPT_KEYSTORETYPE = "keyStoreType";
		private static final String OPT_JDBCPASSWORD = "jdbcPassword";
		private static final String OPT_JDBCUSER = "jdbcUser";
		private static final String OPT_JDBCURL = "jdbcUrl";
		private static final String OPT_JDBCDRIVER = "jdbcDriver";
		private static final String OPT_PROXY = "proxy";
		private static final String OPT_INTERFACE = "interface";
		private static final String OPT_PORT = "port";
		private static final String OPT_CONNECT = "httpConnect";

		private int port = 1080;
		private String iface = "localhost";
		private String proxy = "DIRECT";
		private String jdbcDriver, jdbcUrl, jdbcUser, jdbcPassword;
		private String keystoreType, keyStoreLocation, keyStoreAlias,
				keyStorePassword;
		private int pkcs11SlotLocation = 0;

		private String[] ajpHosts = null;
		private InetSocketAddress ajpServer = null;
		private String ajpUser = null;
		private String ajpClientAddress = "127.0.0.1";
		private String ajpClientCert = null;

		private String authUser, authPassword;

		private InetSocketAddress httpConnect = null;

		@SuppressWarnings("static-access")
		private static Configuration init(String[] args) {
			Options options = new Options();
			options.addOption(OptionBuilder.withLongOpt(OPT_PORT).hasArg()
					.isRequired()
					.withDescription("the port to accept connections on")
					.create());
			options.addOption(OptionBuilder
					.withLongOpt(OPT_INTERFACE)
					.hasArg()
					.withDescription(
							"the network interface to listen on [default localhost]")
					.create());
			options.addOption(OptionBuilder
					.withLongOpt(OPT_PROXY)
					.hasArg()
					.withDescription(
							"proxy instruction for upstream proxy access")
					.create());

			options.addOption(OptionBuilder.withLongOpt(OPT_JDBCDRIVER)
					.hasArg().withDescription("the JDBC driver to use")
					.create());
			options.addOption(OptionBuilder.withLongOpt(OPT_JDBCURL).hasArg()
					.withDescription("the JDBC URL").create());
			options.addOption(OptionBuilder.withLongOpt(OPT_JDBCUSER).hasArg()
					.withDescription("the JDBC username").create());
			options.addOption(OptionBuilder.withLongOpt(OPT_JDBCPASSWORD)
					.hasArg().withDescription("the JDBC password").create());

			options.addOption(OptionBuilder.withLongOpt(OPT_KEYSTORETYPE)
					.hasArg()
					.withDescription("the KeyStore type for client keys")
					.create());
			options.addOption(OptionBuilder.withLongOpt(OPT_KEYSTORELOCATION)
					.hasArg().withDescription("the KeyStore location").create());
			options.addOption(OptionBuilder
					.withLongOpt(OPT_KEYSTOREALIAS)
					.hasArg()
					.withDescription(
							"the alias for the desired key [defaults to the first key]")
					.create());
			options.addOption(OptionBuilder.withLongOpt(OPT_KEYSTOREPASSWORD)
					.hasArg().withDescription("the password for the KeyStore")
					.create());
			options.addOption(OptionBuilder.withLongOpt(OPT_PKCS11SLOTLOCATION)
					.hasArg()
					.withDescription("the index of the hardware token to use")
					.create());

			options.addOption(OptionBuilder
					.withLongOpt(OPT_AJPUSER)
					.hasArg()
					.withDescription(
							"the username to forward to the AJP server")
					.create());
			options.addOption(OptionBuilder
					.withLongOpt(OPT_AJPCLIENTADDRESS)
					.hasArg()
					.withDescription(
							"the client address to forward to the AJP server [default 127.0.0.1]")
					.create());
			options.addOption(OptionBuilder
					.withLongOpt(OPT_AJPSERVER)
					.hasArg()
					.withDescription("the AJP server to connect to [host:port]")
					.create());
			options.addOption(OptionBuilder
					.withLongOpt(OPT_AJPHOST)
					.hasArgs()
					.withDescription(
							"the target domain reachable via the AJP server [can be repeated, missing implies all hosts]")
					.create());

			options.addOption(OptionBuilder.withLongOpt(OPT_AUTHUSER).hasArg()
					.withDescription("the user to authenticate as").create());
			options.addOption(OptionBuilder.withLongOpt(OPT_AUTHPASSWORD)
					.hasArg()
					.withDescription("the password to use when authenticating")
					.create());

			options.addOption(OptionBuilder
					.withLongOpt(OPT_CONNECT)
					.hasArg()
					.withDescription(
							"Uses the specified upstream HTTP proxy to CONNECT to the desired end point [host:port]. Disables all other proxy functionality.")
					.create());

			try {
				CommandLine cmd = new GnuParser().parse(options, args);

				Configuration config = new Configuration();

				if (cmd.hasOption(OPT_INTERFACE))
					config.iface = cmd.getOptionValue(OPT_INTERFACE);
				if (cmd.hasOption(OPT_PORT))
					config.port = Integer
							.parseInt(cmd.getOptionValue(OPT_PORT));
				if (cmd.hasOption(OPT_PROXY))
					config.proxy = cmd.getOptionValue(OPT_PROXY);

				if (cmd.hasOption(OPT_JDBCDRIVER))
					config.jdbcDriver = cmd.getOptionValue(OPT_JDBCDRIVER);
				if (cmd.hasOption(OPT_JDBCURL))
					config.jdbcUrl = cmd.getOptionValue(OPT_JDBCURL);
				if (cmd.hasOption(OPT_JDBCUSER))
					config.jdbcUser = cmd.getOptionValue(OPT_JDBCUSER);
				if (cmd.hasOption(OPT_JDBCPASSWORD))
					config.jdbcPassword = cmd.getOptionValue(OPT_JDBCPASSWORD);

				if (cmd.hasOption(OPT_KEYSTORETYPE))
					config.keystoreType = cmd.getOptionValue(OPT_KEYSTORETYPE);
				if (cmd.hasOption(OPT_KEYSTORELOCATION))
					config.keyStoreLocation = cmd
							.getOptionValue(OPT_KEYSTORELOCATION);
				if (cmd.hasOption(OPT_KEYSTOREPASSWORD))
					config.keyStorePassword = cmd
							.getOptionValue(OPT_KEYSTOREPASSWORD);
				if (cmd.hasOption(OPT_KEYSTOREALIAS))
					config.keyStoreAlias = cmd
							.getOptionValue(OPT_KEYSTOREALIAS);
				if (cmd.hasOption(OPT_PKCS11SLOTLOCATION))
					config.pkcs11SlotLocation = Integer.parseInt(cmd
							.getOptionValue(OPT_PKCS11SLOTLOCATION));

				if (cmd.hasOption(OPT_AJPUSER))
					config.ajpUser = cmd.getOptionValue(OPT_AJPUSER);
				if (cmd.hasOption(OPT_AJPCLIENTADDRESS))
					config.ajpClientAddress = cmd
							.getOptionValue(OPT_AJPCLIENTADDRESS);
				if (cmd.hasOption(OPT_AJPSERVER)) {
					String server = cmd.getOptionValue(OPT_AJPSERVER);
					int colon = server.indexOf(':');
					int port = 8009;
					if (colon > -1) {
						port = Integer.parseInt(server.substring(colon + 1));
						server = server.substring(0, colon - 1);
					}
					config.ajpServer = new InetSocketAddress(server, port);
				}
				if (cmd.hasOption(OPT_AJPHOST))
					config.ajpHosts = cmd.getOptionValues(OPT_AJPHOST);

				if (cmd.hasOption(OPT_AUTHUSER))
					config.authUser = cmd.getOptionValue(OPT_AUTHUSER);
				if (cmd.hasOption(OPT_AUTHPASSWORD))
					config.authPassword = cmd.getOptionValue(OPT_AUTHPASSWORD);

				if (cmd.hasOption(OPT_CONNECT)) {
					String proxy = cmd.getOptionValue(OPT_CONNECT);
					int colon = proxy.indexOf(':');
					int port = 3128;
					if (colon > -1) {
						port = Integer.parseInt(proxy.substring(colon + 1));
						proxy = proxy.substring(0, colon);
						System.out.println("Proxy is " + proxy + ":" + port);
					}
					config.httpConnect = new InetSocketAddress(proxy, port);
				}
				return config;
			} catch (ParseException e) {
				System.out.println(e.getLocalizedMessage());
				// automatically generate the help statement
				HelpFormatter formatter = new HelpFormatter();
				formatter.printHelp(Main.class.getCanonicalName(), options);
				System.exit(2);
				return null;
			}
		}

	}

	private static ProxySelector getProxySelector(Configuration config) {
		String proxy = config.proxy;
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
			InetSocketAddress addr = new InetSocketAddress(
					proxy.substring(0, c), Integer.parseInt(proxy
							.substring(c + 1)));
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

	private static DataSource createDataSource(Configuration config)
			throws SQLException {
		if (config.jdbcDriver == null)
			return null;
		DriverManagerDataSource dataSource = new DriverManagerDataSource();
		dataSource.setDriverClassName(config.jdbcDriver);
		dataSource.setUrl(config.jdbcUrl);
		dataSource.setUsername(config.jdbcUser);
		dataSource.setPassword(config.jdbcPassword);
		return dataSource;
	}

	private static SSLContextSelector getServerSSLContextSelector()
			throws GeneralSecurityException, IOException {
		File ks = new File("ca.p12");
		String type = "PKCS12";
		char[] password = "password".toCharArray();
		String alias = "CA";
		if (ks.exists()) {
			try {
				return new AutoGeneratingContextSelector(ks, type, password,
						password, alias);
			} catch (GeneralSecurityException e) {
				System.err.println("Error loading CA keys from keystore: "
						+ e.getLocalizedMessage());
			} catch (IOException e) {
				System.err.println("Error loading CA keys from keystore: "
						+ e.getLocalizedMessage());
			}
		}
		System.err.println("Generating a new CA");
		X500Principal ca = new X500Principal("cn=OWASP Custom CA for "
				+ java.net.InetAddress.getLocalHost().getHostName()
				+ ",ou=OWASP Custom CA,o=OWASP,l=OWASP,st=OWASP,c=OWASP");
		AutoGeneratingContextSelector ssl = new AutoGeneratingContextSelector(
				ca);
		try {
			ssl.save(ks, type, password, password, alias);
		} catch (GeneralSecurityException e) {
			System.err.println("Error saving CA keys to keystore: "
					+ e.getLocalizedMessage());
		} catch (IOException e) {
			System.err.println("Error saving CA keys to keystore: "
					+ e.getLocalizedMessage());
		}
		FileWriter pem = null;
		try {
			pem = new FileWriter("ca.pem");
			pem.write(ssl.getCACert());
		} catch (IOException e) {
			System.err.println("Error writing CA cert : "
					+ e.getLocalizedMessage());
		} finally {
			if (pem != null)
				pem.close();
		}
		return ssl;
	}

	private static SSLContextSelector getClientSSLContextSelector(
			Configuration config) {
		String type = config.keystoreType;
		char[] password = config.keyStorePassword == null ? null
				: config.keyStorePassword.toCharArray();
		File location = config.keyStoreLocation == null ? null : new File(
				config.keyStoreLocation);
		if (type != null) {
			KeyStore ks = null;
			if (type.equals("PKCS11")) {
				try {
					int slot = config.pkcs11SlotLocation;
					ks = KeystoreUtils.getPKCS11Keystore("PKCS11", location,
							slot, password);
				} catch (Exception e) {
					System.err.println(e.getLocalizedMessage());
					System.exit(2);
				}
			} else {
				try {
					FileInputStream in = new FileInputStream(location);
					ks = KeyStore.getInstance(type);
					ks.load(in, password);
				} catch (Exception e) {
					System.err.println(e.getLocalizedMessage());
					System.exit(2);
				}
			}
			String alias = config.keyStoreAlias;
			if (alias == null) {
				try {
					Map<String, String> aliases = KeystoreUtils.getAliases(ks);
					if (aliases.size() > 0) {
						System.err
								.println("Keystore contains the following aliases: \n");
						for (String a : aliases.keySet()) {
							System.err.println("Alias \"" + a + "\"" + " : "
									+ aliases.get(a));
						}
						alias = aliases.keySet().iterator().next();
						System.err.println("Using " + alias + " : "
								+ aliases.get(alias));
					} else {
						System.err.println("Keystore contains no aliases!");
						System.exit(3);
					}
				} catch (KeyStoreException kse) {
					System.err.println(kse.getLocalizedMessage());
					System.exit(4);
				}
			}
			try {
				final X509KeyManager km = KeystoreUtils.getKeyManagerForAlias(
						ks, alias, password);
				return new DefaultClientContextSelector(km);
			} catch (GeneralSecurityException gse) {
				System.err.println(gse.getLocalizedMessage());
				System.exit(5);
			}
		}
		return new DefaultClientContextSelector();
	}

	private static DefaultHttpRequestHandler configureRequestHandler(
			Configuration config) {
		final ProxySelector ps = getProxySelector(config);
		final SSLContextSelector sslc = getClientSSLContextSelector(config);

		return new DefaultHttpRequestHandler() {
			@Override
			protected HttpClient createClient() {
				HttpClient client = super.createClient();
				client.setSslContextSelector(sslc);
				client.setProxySelector(ps);
				client.setSoTimeout(90000);
				return client;
			}
		};
	}

	private static HttpRequestHandler configureAuthentication(
			HttpRequestHandler rh, final Configuration config) {
		if (config.authUser != null) {
			if (config.authPassword == null) {
				System.err.println("authPassword must be provided!");
				System.exit(1);
			}
			Authenticator.setDefault(new Authenticator() {
				@Override
				protected PasswordAuthentication getPasswordAuthentication() {
					return new PasswordAuthentication(config.authUser,
							config.authPassword.toCharArray());
				}
			});
			return new AuthenticatingHttpRequestHandler(rh);
		} else {
			return rh;
		}
	}

	private static HttpRequestHandler configureAJP(HttpRequestHandler rh,
			Configuration config) {
		if (config.ajpServer != null) {
			final DefaultAJPRequestHandler arh = new DefaultAJPRequestHandler();
			arh.setTarget(config.ajpServer);
			AJPProperties ajpProperties = new AJPProperties();
			ajpProperties.setRemoteAddress(config.ajpClientAddress);
			if (config.ajpClientCert != null
					&& config.ajpClientCert.endsWith(".pem")) {
				try {
					BufferedReader in = new BufferedReader(new FileReader(
							config.ajpClientCert));
					StringBuffer buff = new StringBuffer();
					String line;
					while ((line = in.readLine()) != null) {
						buff.append(line);
					}
					in.close();
					ajpProperties.setSslCert(buff.toString());
					ajpProperties.setSslCipher("ECDHE-RSA-AES256-SHA");
					ajpProperties.setSslSession("RANDOMID");
					ajpProperties.setSslKeySize("256");
				} catch (IOException ioe) {
					ioe.printStackTrace();
					System.exit(1);
				}
			}
			ajpProperties.setRemoteUser(config.ajpUser);
			ajpProperties.setAuthType("BASIC");
			ajpProperties.setContext("/manager");
			arh.setProperties(ajpProperties);
			final Set<String> ajpHosts = new HashSet<String>();
			if (config.ajpHosts != null)
				ajpHosts.addAll(Arrays.asList(config.ajpHosts));
			final HttpRequestHandler hrh = rh;
			return new HttpRequestHandler() {

				@Override
				public StreamingResponse handleRequest(InetAddress source,
						StreamingRequest request, boolean isContinue)
						throws IOException, MessageFormatException {
					InetSocketAddress target = request.getTarget();
					if (ajpHosts.isEmpty()
							|| ajpHosts.contains(target.getHostName())
							|| ajpHosts.contains(target.getAddress()
									.getHostAddress())) {
						return arh.handleRequest(source, request, isContinue);
					} else {
						return hrh.handleRequest(source, request, isContinue);
					}
				}

				@Override
				public void dispose() throws IOException {
					arh.dispose();
					hrh.dispose();
				}

			};
		} else {
			return rh;
		}
	}

	private static HttpRequestHandler configureJDBCLogging(
			HttpRequestHandler rh, Configuration config) throws SQLException {
		final DataSource dataSource = createDataSource(config);
		if (dataSource != null) {
			JdbcMessageDAO dao = new JdbcMessageDAO();
			dao.setDataSource(dataSource);
			dao.createTables();
			rh = new RecordingHttpRequestHandler(dao, rh, 1024 * 1024);
			return new ConversationServiceHttpRequestHandler("127.0.0.2", dao,
					rh);
		} else {
			return rh;
		}
	}

	private static HttpRequestHandler configureInterception(
			HttpRequestHandler rh, Configuration config) {
		BufferedMessageInterceptor bmi = new BufferedMessageInterceptor() {
			@Override
			public Action directResponse(RequestHeader request,
					MutableResponseHeader response) {
				// System.err.println(new String(request.getHeader())
				// + "+++++++++++\n" + new String(response.getHeader())
				// + "===========");
				return Action.STREAM;
			}

			@Override
			public Action directRequest(MutableRequestHeader request) {
				// System.err.println(new String(request.getHeader())
				// + "===========");
				return Action.STREAM;
			}
		};
		return new BufferingHttpRequestHandler(rh, bmi, 10240);
	}

	public static void main(String[] args) throws Exception {
		java.lang.System.setProperty(
				"sun.security.ssl.allowUnsafeRenegotiation", "true");
		logger.setUseParentHandlers(false);
		Handler ch = new ConsoleHandler();
		ch.setFormatter(new TextFormatter());
		logger.addHandler(ch);

		final Configuration config = Configuration.init(args);

		final InetSocketAddress listen = new InetSocketAddress(config.iface,
				config.port);
		TargetedConnectionHandler tch;
		if (config.httpConnect == null) {
			DefaultHttpRequestHandler drh = configureRequestHandler(config);
			ServerGroup sg = new ServerGroup();
			sg.addServer(listen);
			drh.setServerGroup(sg);
	
			HttpRequestHandler rh = drh;
			rh = configureAuthentication(rh, config);
			rh = configureAJP(rh, config);
			rh = new LoggingHttpRequestHandler(rh);
			rh = configureJDBCLogging(rh, config);
			rh = configureInterception(rh, config);
	
			HttpProxyConnectionHandler hpch = new HttpProxyConnectionHandler(rh);
			SSLContextSelector cp = getServerSSLContextSelector();
			tch = new SSLConnectionHandler(cp, true, hpch);
			tch = new LoopAvoidingTargetedConnectionHandler(sg, tch);
			hpch.setConnectHandler(tch);
		} else {
			tch = new ConnectConnectionHandler(config.httpConnect);
		}
		TargetedConnectionHandler socks = new SocksConnectionHandler(tch, true);
		Proxy p = new Proxy(listen, socks, null);
		p.setSocketTimeout(90000);
		p.start();

		System.out.println("Listener started on " + listen);
		System.out.println("Press Enter to terminate");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		p.stop();
		System.out.println("Terminated");
		System.exit(0);
	}
}
