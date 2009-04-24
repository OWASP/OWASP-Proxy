/*
 *  This file is part of the OWASP Proxy, a free intercepting proxy
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

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.io.PushbackSocket;

/**
 * This class implements an intercepting proxy. The user is required to override
 * the {@link #createProtocolHandler(Socket, InetSocketAddress, boolean)} method
 * to implement the required protocol.
 * 
 * This class has built-in support for auto-detecting SOCKS and SSL protocols,
 * and will perform the relevant negotiation when appropriate. This behaviour
 * can be controlled by using the
 * {@link #Proxy(InetSocketAddress, InetSocketAddress, SOCKS, SSL)} constructor
 * if necessary.
 * 
 * If SOCKS support is disabled, and the protocol provides no method to
 * determine the desired target destination, you should specify a target for
 * connections to be relayed to. This target address will be passed directly to
 * {@link #createProtocolHandler(Socket, InetSocketAddress, boolean)}.
 * 
 * The most basic proxy might look like:
 * 
 * <code>
 * 	InetSocketAddress address = new InetSocketAddress("localhost", 8008);
 * 	Proxy proxy = new Proxy(address) {
 *  	protected Runnable createProtocolHandler(final Socket sock, final InetSocketAddress target, boolean ssl) {
 *  		return new Runnable() {
 *  			public void run() {
 *  				try {
 *  				Socket dst = new Socket();
 *  				dst.connect(target);
 *  				new SocketPipe(sock, dst).connect();
 *  			}
 *  		};
 *  	}
 *  }; 
 * 	proxy.start();
 * 	
 * 	<wait for signal to stop>
 * 	
 * 	if (!proxy.stop()) {
 * 		// error stopping proxy 
 * 	}
 * </code>
 * 
 * Note: The above proxy does not support SSL connections (since it does not
 * check the "ssl" parameter), and will simply relay unencrypted data to the
 * destination.
 * 
 * This proxy allows provision of target-specific SSL server certificates, by
 * overriding the {@link #getSSLSocketFactory(InetSocketAddress)} method.
 * 
 * If you need more complex SSL protocol handling than is provided by this
 * proxy, simply specifiy SSL.NEVER, and handle it in your own class.
 * 
 * @author Rogan Dawes
 * 
 */
public abstract class Proxy {

	private final static Logger logger = Logger
			.getLogger(Proxy.class.getName());

	public enum SSL {
		NEVER, ALWAYS, AUTO
	};

	public enum SOCKS {
		NEVER, ALWAYS, AUTO
	};

	private volatile ServerSocket socket = null;

	private SSL ssl;

	private SOCKS socks;

	private InetSocketAddress target;

	private int socketTimeout = 0;

	public Proxy(InetSocketAddress listen) throws IOException {
		this(listen, null, SOCKS.AUTO, SSL.AUTO);
	}

	public Proxy(InetSocketAddress listen, InetSocketAddress target,
			SOCKS socks, SSL ssl) throws IOException {
		if (socks == null)
			socks = SOCKS.AUTO;
		if (ssl == null)
			ssl = SSL.AUTO;
		if (target != null && socks != SOCKS.NEVER)
			throw new IllegalArgumentException(
					"You cannot specify a target as well as allowing SOCKS negotiation");
		this.target = target;
		this.socks = socks;
		this.ssl = ssl;
		socket = new ServerSocket(listen.getPort(), 20, listen.getAddress());
		socket.setReuseAddress(true);
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

	private SSLSocketFactory sslSocketFactory = null;

	protected SSLSocketFactory getSSLSocketFactory(InetSocketAddress target)
			throws GeneralSecurityException {
		if (sslSocketFactory == null) {
			try {
				DefaultCertificateProvider cp = new DefaultCertificateProvider();
				sslSocketFactory = cp.getSocketFactory(null, -1);
			} catch (IOException ioe) {
				throw new GeneralSecurityException(ioe);
			}
		}
		return sslSocketFactory;
	}

	protected abstract Runnable createProtocolHandler(Socket socket,
			InetSocketAddress target, boolean ssl);

	private byte[] sniff(PushbackSocket socket, int len) throws IOException {
		PushbackInputStream in = socket.getInputStream();
		byte[] sniff = new byte[len];
		int read = 0, attempt = 0;
		do {
			int got = in.read(sniff, read, sniff.length - read);
			if (got == -1)
				return null;
			read += got;
			attempt++;
		} while (read < sniff.length && attempt < sniff.length);
		if (read < sniff.length)
			throw new IOException("Failed to read " + len
					+ " bytes in as many attempts!");
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
		SSLSocketFactory factory = getSSLSocketFactory(target);
		if (factory == null)
			return null;
		SSLSocket sslsock = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		sslsock.setUseClientMode(false);
		return sslsock;
	}

	private Runnable getConnectionHandler(PushbackSocket socket)
			throws IOException {
		socket.setSoTimeout(socketTimeout);

		InetSocketAddress target = this.target;

		boolean socks = false;
		if (this.socks.equals(SOCKS.AUTO)) {
			// check if it is a SOCKS request
			byte[] sniff = sniff(socket, 1);
			if (sniff == null) // connection closed
				return null;

			if (sniff[0] == 4 || sniff[0] == 5) // SOCKS v4 or V5
				socks = true;
		} else if (this.socks.equals(SOCKS.ALWAYS))
			socks = true;

		if (socks) {
			SocksProtocolHandler sp = new SocksProtocolHandler(socket, null);
			target = sp.handleConnectRequest();
		}

		boolean ssl = false;
		if (this.ssl.equals(SSL.AUTO)) {
			// check if it is an SSL connection
			byte[] sniff = sniff(socket, 4);
			if (sniff == null) // connection closed
				return null;

			if (isSSL(sniff))
				ssl = true;
		} else if (this.ssl.equals(SSL.ALWAYS))
			ssl = true;

		Socket sock = socket;
		if (ssl) {
			try {
				sock = negotiateSsl(sock, target);
			} catch (GeneralSecurityException gse) {
				logger.warning("Error negotiating SSL: " + gse.getMessage());
				return null;
			}
		}

		return createProtocolHandler(sock, target, ssl);
	}

	private void handleConnection(Socket accept) throws IOException {
		final PushbackSocket socket = new PushbackSocket(accept);
		Thread thread = new Thread() {
			public void run() {
				try {
					Runnable r = getConnectionHandler(socket);
					if (r != null)
						r.run();
				} catch (IOException ioe) {
					logger.severe("Error creating connection handler!"
							+ ioe.getMessage());
				} finally {
					try {
						socket.close();
					} catch (IOException ignore) {
					}
				}
			}
		};
		thread.setDaemon(true);
		thread.start();
	}

	private AcceptThread acceptThread = null;

	private class AcceptThread extends Thread {

		public void run() {
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
			synchronized (this) {
				notifyAll();
			}
		}
	}

	public synchronized void start() {
		if (acceptThread == null) {
			acceptThread = new AcceptThread();
			acceptThread.setDaemon(true);
		} else if (acceptThread.isAlive()) {
			throw new IllegalStateException(
					"Already running in another thread!");
		}
		acceptThread.start();
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
		return true;
	}

	public synchronized boolean isStopped() {
		return socket == null || socket.isClosed();
	}

}
