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
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.util.logging.Logger;

/**
 * This class implements a TCP server. The user is required to provide an
 * implementation of {@link ConnectionHandler} implementing the desired
 * protocol.
 * 
 * The most basic (echo) server might look like:
 * 
 * <code>
 * 	InetSocketAddress address = new InetSocketAddress("localhost", 8008);
 * 	Server echo = new server(address, new ConnectionHandler() {
 *  	protected void handleConnection(Socket socket) throws IOException {
 *  		InputStream in = socket.getInputStream();
 *  		OutputStream out = socket.getOutputStream();
 *  		byte[] buff = new byte[1024];
 *  		int got;
 *  		while ((got = in.read(buff)) > -1)
 *  			out.write(buff, 0, got);
 *  	}
 *  }); 
 * 	echo.start();
 * 	
 * 	<wait for signal to stop>
 * 	
 * 	if (!echo.stop()) {
 * 		// error stopping server 
 * 	}
 * </code>
 * 
 * @author Rogan Dawes
 * 
 */
public class Server {

	private final static Logger logger = Logger.getLogger(Server.class
			.getName());

	private ServerSocket socket;

	private int socketTimeout = 0;

	private ConnectionHandler connectionHandler;

	public Server(InetSocketAddress listen, ConnectionHandler connectionHandler)
			throws IOException {
		if (listen == null)
			throw new NullPointerException("listen may not be null");
		if (connectionHandler == null)
			throw new NullPointerException("connectionHandler may not be null");
		socket = new ServerSocket(listen.getPort(), 20, listen.getAddress());
		socket.setReuseAddress(true);
		this.connectionHandler = connectionHandler;
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

	private void handleConnection(final Socket socket) throws IOException {
		Thread thread = new Thread() {
			public void run() {
				try {
					socket.setSoTimeout(socketTimeout);
					connectionHandler.handleConnection(socket);
				} catch (Exception ignore) {
					ignore.printStackTrace();
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
				if (!socket.isClosed()) {
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
			synchronized (Server.this) {
				Server.this.notifyAll();
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
		return acceptThread == null || !acceptThread.isAlive();
	}

}
