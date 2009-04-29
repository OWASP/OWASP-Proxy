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
import java.util.logging.Logger;

import org.owasp.proxy.io.PushbackSocket;

/**
 * This class implements an intercepting proxy. The user is required to override
 * the {@link #handleConnection(Socket, InetSocketAddress)} method to implement
 * the required protocol.
 * 
 * This class has built-in support for auto-detecting the SOCKS protocol, and
 * will perform the negotiation when appropriate. This behaviour can be
 * controlled by using the
 * {@link #Proxy(InetSocketAddress, InetSocketAddress, SOCKS)} constructor if
 * necessary.
 * 
 * If SOCKS support is disabled, and the protocol itself provides no method to
 * determine the desired target destination, you should specify a target for
 * connections to be relayed to. This target address will be passed directly to
 * {@link #createProtocolHandler(Socket, InetSocketAddress, boolean)}.
 * 
 * The most basic proxy might look like:
 * 
 * <code>
 * 	InetSocketAddress address = new InetSocketAddress("localhost", 8008);
 * 	Proxy proxy = new Proxy(address, null, Proxy.SOCKS.AUTO) {
 *  	protected void handleConnection(final Socket sock, final InetSocketAddress target) {
 * 			try {
 * 				Socket dst = new Socket(target.getInetAddress(), target.getPort());
 * 				new SocketPipe(sock, dst).connect();
 * 			} catch (IOException ignore) {}
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
 * @author Rogan Dawes
 * 
 */
public abstract class Proxy {

	private final static Logger logger = Logger
			.getLogger(Proxy.class.getName());

	public enum SOCKS {
		NEVER, ALWAYS, AUTO
	};

	private volatile ServerSocket socket = null;

	private SOCKS socks;

	private InetSocketAddress target;

	private int socketTimeout = 0;

	public Proxy(InetSocketAddress listen, InetSocketAddress target, SOCKS socks)
			throws IOException {
		if (socks == null)
			socks = SOCKS.AUTO;
		if (target != null && socks != SOCKS.NEVER)
			throw new IllegalArgumentException(
					"You cannot specify a target as well as allowing SOCKS negotiation");
		this.target = target;
		this.socks = socks;
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

	private Thread createConnectionHandler(final Socket socket)
			throws IOException {
		Thread thread = new Thread() {
			public void run() {
				try {
					handleConnection(socket);
				} catch (IOException ignore) {
				} finally {
					try {
						if (!socket.isClosed())
							socket.close();
					} catch (IOException ignore) {
					}
				}
			}
		};
		thread.setDaemon(true);
		return thread;
	}

	private void handleConnection(Socket accept) throws IOException {
		final PushbackSocket socket = new PushbackSocket(accept);
		socket.setSoTimeout(socketTimeout);

		InetSocketAddress target = this.target;

		boolean socks = false;
		if (this.socks.equals(SOCKS.AUTO)) {
			// check if it is a SOCKS request
			byte[] sniff = sniff(socket, 1);
			if (sniff == null) // connection closed
				return;

			if (sniff[0] == 4 || sniff[0] == 5) // SOCKS v4 or V5
				socks = true;
		} else if (this.socks.equals(SOCKS.ALWAYS))
			socks = true;

		if (socks) {
			SocksProtocolHandler sp = new SocksProtocolHandler(socket, null);
			target = sp.handleConnectRequest();
		}

		handleConnection(socket, target);
	}

	protected abstract void handleConnection(Socket socket,
			InetSocketAddress target) throws IOException;

	private AcceptThread acceptThread = null;

	private class AcceptThread extends Thread {

		public void run() {
			try {
				do {
					createConnectionHandler(socket.accept()).start();
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
