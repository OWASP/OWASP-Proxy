/*
 *  This file is part of the OWASP Proxy, a free intercepting HTTP proxy
 *  library.
 *  Copyright (C) 2008  Rogan Dawes <rogan@dawes.za.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
package org.owasp.proxy.daemon;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.GeneralSecurityException;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.httpclient.HttpClientFactory;
import org.owasp.proxy.io.PushbackSocket;

/**
 * This class implements an intercepting HTTP proxy, which can be customized to
 * modify and/or log the conversations passing through it in various ways. It
 * also supports streaming large responses directly to the browser, although
 * this behaviour can be controlled on a per-request basis.
 * 
 * The most basic proxy (that has no customized behaviour) should look like:
 * 
 * <code>
 * 	int port = . . .;
 * 	Listener listener = new Listener(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), port); 
 * 	Thread t = new Thread(listener);
 * 	t.setDaemon(true);
 * 	t.start();
 * 	
 * 	<wait for signal to stop>
 * 	
 * 	if (!listener.stop()) {
 * 		// error stopping listener 
 * 	}
 * </code>
 * 
 * Observing and influencing the proxy is accomplished through the ProxyMonitor.
 * 
 * @see Listener#setProxyMonitor(BufferedProxyMonitor)
 * @see BufferedProxyMonitor
 * 
 * @author Rogan Dawes
 * 
 */
public class Listener {

	private Configuration config;

	private volatile ServerSocket socket = null;

	private final static Logger logger = Logger.getLogger(Listener.class
			.getName());

	private static Set<SocketAddress> listenAddresses = new HashSet<SocketAddress>();

	public static synchronized SocketAddress[] getListeners() {
		return listenAddresses
				.toArray(new SocketAddress[listenAddresses.size()]);
	}

	protected static synchronized void registerListener(SocketAddress addr) {
		listenAddresses.add(addr);
	}

	protected static synchronized void deregisterListener(SocketAddress addr) {
		listenAddresses.remove(addr);
	}

	public Listener(Configuration config) throws IOException {
		this.config = config;
		InetSocketAddress listen = config.getListenerAddress();
		socket = new ServerSocket(listen.getPort(), 20, listen.getAddress());
		socket.setReuseAddress(true);
	}

	private byte[] sniff(PushbackSocket socket) throws IOException {
		PushbackInputStream in = socket.getInputStream();
		byte[] sniff = new byte[4];
		int read = 0, attempt = 0;
		do {
			int got = in.read(sniff, read, sniff.length - read);
			if (got == -1)
				return null;
			read += got;
			attempt++;
		} while (read < sniff.length && attempt < 4);
		if (read < sniff.length)
			throw new IOException("Failed to read 4 bytes in 4 attempts!");
		in.unread(sniff);
		return sniff;
	}

	private boolean isSSL(byte[] sniff) {
		for (int i = 0; i < sniff.length; i++)
			if (sniff[i] == 0x03)
				return true;
		return false;
	}

	private SSLSocket negotiateSsl(Socket socket, InetSocketAddress target)
			throws GeneralSecurityException, IOException {
		CertificateProvider cp = config.getCertificateProvider();
		if (cp == null)
			return null;

		SSLSocketFactory factory = cp.getSocketFactory(target.getHostName(),
				target.getPort());
		if (factory == null)
			return null;
		SSLSocket sslsock = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		sslsock.setUseClientMode(false);
		return sslsock;
	}

	protected ConnectionHandler createConnectionHandler(PushbackSocket socket,
			ConnectionHandler.Configuration c) throws IOException {
		socket.setSoTimeout(config.getSocketTimeout());

		// check if it is an SSL connection
		byte[] sniff = sniff(socket);
		if (sniff == null) // connection closed
			return null;

		if (isSSL(sniff)) {
			c.setSsl(true);
			try {
				return new ConnectionHandler(
						negotiateSsl(socket, c.getTarget()), c);
			} catch (GeneralSecurityException gse) {
				gse.printStackTrace();
				socket.close();
				return null;
			}
		} else {
			return new ConnectionHandler(socket, c);
		}
	}

	private void handleConnection(Socket accept) throws IOException {
		final PushbackSocket pbs = new PushbackSocket(accept);
		Thread thread = new Thread(new Runnable() {

			public void run() {
				try {
					ConnectionHandler.Configuration c = new ConnectionHandler.Configuration();
					c.setTarget(config.getTarget());
					c.setCertificateProvider(config.getCertificateProvider());
					c.setHttpClientFactory(config.getHttpClientFactory());
					c.setProxyMonitor(config.getProxyMonitor());

					ConnectionHandler ch = createConnectionHandler(pbs, c);
					ch.run();
				} catch (IOException ioe) {
					try {
						pbs.close();
					} catch (IOException ignore) {
					}
					logger.severe("Error creating connection handler!"
							+ ioe.getMessage());
				}
			}
		});
		thread.setDaemon(true);
		thread.start();
	}

	private Runner runner = null;

	private class Runner implements Runnable {

		public void run() {
			SocketAddress addr = socket.getLocalSocketAddress();
			registerListener(addr);
			try {
				do {
					handleConnection(socket.accept());
				} while (!socket.isClosed());
			} catch (IOException ioe) {
				if (!isStopped()) {
					ioe.printStackTrace();
					logger.warning("Exception listening for connections: "
							+ ioe.getMessage());
				}
			}
			try {
				if (socket != null && !socket.isClosed())
					socket.close();
			} catch (IOException ioe) {
				logger.warning("Exception closing socket: " + ioe.getMessage());
			}
			deregisterListener(addr);
			synchronized (this) {
				notifyAll();
			}
		}
	}

	public synchronized void start() {
		if (runner != null)
			throw new IllegalStateException(
					"Already running in another thread!");
		runner = new Runner();
		Thread thread = new Thread(runner);
		thread.setDaemon(true);
		thread.start();
	}

	public synchronized boolean stop() {
		if (!isStopped()) {
			try {
				socket.close();
			} catch (IOException ioe) {
				ioe.printStackTrace();
			}
			while (!isStopped()) {
				int loop = 0;
				try {
					wait(1000);
				} catch (InterruptedException ie) {
					loop++;
					if (loop > 10)
						return false;
				}
			}
		}
		runner = null;
		return true;
	}

	public synchronized boolean isStopped() {
		return socket == null || socket.isClosed();
	}

	public static class Configuration {

		private CertificateProvider certificateProvider;

		private ProxyMonitor proxyMonitor;

		private InetSocketAddress target = null;

		private InetSocketAddress listenerAddress;

		private HttpClientFactory httpClientFactory;

		private int socketTimeout = 60000;

		public Configuration(InetSocketAddress listenerAddress) {
			this.listenerAddress = listenerAddress;
		}

		/**
		 * @return the certificateProvider
		 */
		public CertificateProvider getCertificateProvider() {
			return certificateProvider;
		}

		/**
		 * @param certificateProvider
		 *            the certificateProvider to set
		 */
		public void setCertificateProvider(
				CertificateProvider certificateProvider) {
			this.certificateProvider = certificateProvider;
		}

		/**
		 * @return the httpClientFactory
		 */
		public HttpClientFactory getHttpClientFactory() {
			return httpClientFactory;
		}

		/**
		 * @param httpClientFactory
		 *            the httpClientFactory to set
		 */
		public void setHttpClientFactory(HttpClientFactory httpClientFactory) {
			this.httpClientFactory = httpClientFactory;
		}

		/**
		 * @return the proxyMonitor
		 */
		public ProxyMonitor getProxyMonitor() {
			return proxyMonitor;
		}

		/**
		 * @param proxyMonitor
		 *            the proxyMonitor to set
		 */
		public void setProxyMonitor(ProxyMonitor proxyMonitor) {
			this.proxyMonitor = proxyMonitor;
		}

		/**
		 * @return the socketTimeout
		 */
		public int getSocketTimeout() {
			return socketTimeout;
		}

		/**
		 * @param socketTimeout
		 *            the socketTimeout to set
		 */
		public void setSocketTimeout(int socketTimeout) {
			this.socketTimeout = socketTimeout;
		}

		/**
		 * @return the target
		 */
		public InetSocketAddress getTarget() {
			return target;
		}

		/**
		 * @param target
		 *            the target to set
		 */
		public void setTarget(InetSocketAddress target) {
			this.target = target;
		}

		/**
		 * @return the listenerAddress
		 */
		public InetSocketAddress getListenerAddress() {
			return listenerAddress;
		}

	}

	public static void main(String[] args) throws Exception {
		InetSocketAddress listener = new InetSocketAddress("localhost", 9998);
		Configuration c = new Configuration(listener);
		c.setProxyMonitor(new LoggingProxyMonitor());
		c.setCertificateProvider(new DefaultCertificateProvider());
		Listener l = new Listener(c);
		l.start();

		System.out.println("Listener started, press Enter to exit");

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
