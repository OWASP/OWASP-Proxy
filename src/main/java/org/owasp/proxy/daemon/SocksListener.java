package org.owasp.proxy.daemon;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.owasp.proxy.daemon.socks.ServerAuthenticator;

public class SocksListener extends Listener {

	private ServerAuthenticator auth;

	/**
	 * Creates a proxy server with given Authentication scheme.
	 * 
	 * @param auth
	 *            Authentication scheme to be used.
	 */
	public SocksListener(Configuration config) throws IOException {
		super(config);
	}

	public void setAuthenticator(ServerAuthenticator authenticator) {
		this.auth = authenticator;
	}

	@Override
	protected ConnectionHandler createConnectionHandler(Socket socket)
			throws IOException {
		System.out
				.println("Connection from " + socket.getRemoteSocketAddress());
		SocksProtocolHandler sp = new SocksProtocolHandler(socket, auth);
		InetSocketAddress target = sp.handleConnectRequest();
		ConnectionHandler ch = super.createConnectionHandler(socket);
		ch.getConfiguration().setTarget(target);
		System.err.println(Thread.currentThread().getName() + ": Target is "
				+ target);
		return ch;
	}

	public static void main(String[] args) throws Exception {
		InetSocketAddress listen = InetSocketAddress.createUnresolved(
				"localhost", 9997);
		Configuration c = new Configuration(listen);
		c.setProxyMonitor(new LoggingProxyMonitor());
		c.setCertificateProvider(new DefaultCertificateProvider());
		Listener l = new SocksListener(c);
		l.start();

		System.out.println("Socks Listener started, press Enter to exit");

		new BufferedReader(new InputStreamReader(System.in)).readLine();

		System.out.println("Exiting!");
		long s = System.currentTimeMillis();
		if (!l.stop()) {
			System.err.println("Failed to exit after "
					+ (System.currentTimeMillis() - s));
		} else {
			System.out.println("Exited in " + (System.currentTimeMillis() - s));
		}
	}

}
