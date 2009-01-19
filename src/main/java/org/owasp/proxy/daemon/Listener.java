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
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketAddress;
import java.util.HashSet;
import java.util.Set;
import java.util.logging.Logger;

import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.httpclient.HttpClientFactory;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.MessageFormatException;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

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
 * @see Listener#setProxyMonitor(ProxyMonitor)
 * @see ProxyMonitor
 * 
 * @author Rogan Dawes
 * 
 */
public class Listener {

	private boolean ssl = false;

	private String host;

	private int port;

	private CertificateProvider certProvider = null;

	private ProxyMonitor monitor;

	private HttpClientFactory clientFactory;

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

	public Listener(int listenPort) throws IOException {
		this(InetAddress.getByAddress(new byte[] { 127, 0, 0, 1 }), listenPort);
	}

	public Listener(InetAddress address, int listenPort) throws IOException {
		socket = new ServerSocket(listenPort, 20, address);
		socket.setReuseAddress(true);
	}

	public void setTarget(boolean ssl, String host, int port) {
		this.ssl = ssl;
		this.host = host;
		this.port = port;
	}

	public void setProxyMonitor(ProxyMonitor monitor) {
		this.monitor = monitor;
	}

	public void setCertificateProvider(CertificateProvider certProvider) {
		this.certProvider = certProvider;
	}

	public void setHttpClientFactory(HttpClientFactory clientFactory) {
		this.clientFactory = clientFactory;
	}

	protected ConnectionHandler createConnectionHandler(Socket socket)
			throws IOException {
		ConnectionHandler ch = new ConnectionHandler(socket);
		ch.setTarget(ssl, host, port);
		ch.setProxyMonitor(monitor);
		ch.setCertificateProvider(certProvider);
		ch.setHttpClientFactory(clientFactory);
		return ch;
	}

	private void handleConnection(final Socket accept) {
		Thread thread = new Thread(new Runnable() {

			public void run() {
				try {
					ConnectionHandler ch = createConnectionHandler(accept);
					ch.run();
				} catch (IOException ioe) {
					try {
						accept.close();
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

	protected HttpClient createHttpClient() {
		return new HttpClient();
	}

	public static void main(String[] args) throws Exception {
		Listener l = new Listener(InetAddress.getByAddress(new byte[] { 127, 0,
				0, 1 }), 9998);
		l.setProxyMonitor(new LoggingProxyMonitor() {

			@Override
			public Response requestReceived(Request request)
					throws MessageFormatException {
				Response ret = super.requestReceived(request);
				// try {
				// System.out.write(request.getMessage());
				// } catch (IOException ioe) {
				// }
				return ret;
			}

			@Override
			public boolean responseHeaderReceived(Conversation conversation)
					throws MessageFormatException {
				return true;
			}

			@Override
			public void responseContentReceived(Conversation conversation,
					boolean streamed) throws MessageFormatException {
				// try {
				// System.err.write(conversation.getResponse().getHeader());
				// } catch (IOException ioe) {
				// }
			}

			@Override
			public void wroteResponseToBrowser(Conversation conversation)
					throws MessageFormatException {
				super.wroteResponseToBrowser(conversation);
			}

		});
		l.setCertificateProvider(new DefaultCertificateProvider());
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
