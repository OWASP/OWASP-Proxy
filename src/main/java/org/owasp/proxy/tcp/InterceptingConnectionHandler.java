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

package org.owasp.proxy.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.daemon.TargetedConnectionHandler;
import org.owasp.proxy.ssl.EncryptedConnectionHandler;
import org.owasp.proxy.ssl.SSLContextSelector;

/**
 * This {@link TargetedConnectionHandler} provides a framework for intercepting
 * arbitrary TCP socket-based protocols.
 * 
 * It establishes a connection to the indicated target, then instantiates a pair
 * of threads that read from the accepted socket and the target socket, and
 * notify the {@link StreamInterceptor} provided when data has been read, or the
 * connection terminated.
 * 
 * The basic sequence is as follows:
 * <ul>
 * <li>A pair of threads are created, one reading from the accepted socket, and
 * the other reading from the socket connected to the target.</li>
 * <li>The {@link StreamInterceptor#connected(StreamHandle, StreamHandle)}
 * method is called, passing the {@link StreamHandle}'s responsible for reading
 * from the accepted socket, and from the target (in that order)</li>
 * <li>As each StreamHandle reads from its socket, it calls
 * {@link StreamInterceptor#received(StreamHandle, byte[], int, int)} with the
 * data read. The StreamHandle serves as a key to inform the StreamInterceptor
 * which socket the data relates to.</li>
 * <li>If there is an error reading from the socket, the StreamHandle calls
 * {@link StreamInterceptor#readException(StreamHandle, IOException)}</li>
 * <li>Finally, {@link StreamInterceptor#inputClosed(StreamHandle)} is always
 * called to allow the StreamInterceptor to release any allocated resources.</li>
 * </ul>
 * 
 * Note that it is still possible to write data to the StreamHandle even after
 * the input has been closed, to allow for modification of the last packet sent.
 * 
 * @author rogan
 * 
 */
public class InterceptingConnectionHandler implements
		TargetedConnectionHandler, EncryptedConnectionHandler {

	private StreamInterceptor<InetSocketAddress, InetSocketAddress> interceptor;

	private SSLContextSelector contextSelector;

	public InterceptingConnectionHandler(
			StreamInterceptor<InetSocketAddress, InetSocketAddress> interceptor) {
		if (interceptor == null)
			throw new IllegalArgumentException("Interceptor may not be null");
		this.interceptor = interceptor;
	}

	public void setSSLContextSelector(SSLContextSelector contextSelector) {
		this.contextSelector = contextSelector;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.TargetedConnectionHandler#handleConnection(java
	 * .net.Socket, java.net.InetSocketAddress)
	 */
	@Override
	public void handleConnection(final Socket client, InetSocketAddress target)
			throws IOException {
		Socket server = new Socket(Proxy.NO_PROXY);
		server.connect(target);
		relay(client, server);
	}

	@Override
	public void handleConnection(Socket client, InetSocketAddress target,
			boolean ssl) throws IOException {
		Socket server = new Socket(Proxy.NO_PROXY);
		server.connect(target);
		if (ssl) {
			server = layerSsl(server, target);
		}
		relay(client, server);
	}

	private void relay(Socket client, Socket server) throws IOException {
		InetSocketAddress clientLabel, serverLabel;
		InputStream ci, si;
		OutputStream so, co;
		StreamRelay<InetSocketAddress, InetSocketAddress> sr;

		clientLabel = (InetSocketAddress) client.getRemoteSocketAddress();
		ci = client.getInputStream();
		co = client.getOutputStream();
		serverLabel = (InetSocketAddress) server.getRemoteSocketAddress();
		si = server.getInputStream();
		so = server.getOutputStream();
		sr = new StreamRelay<InetSocketAddress, InetSocketAddress>(interceptor,
				clientLabel, ci, co, serverLabel, si, so);
		Runnable cch = new Closer(server);
		Runnable sch = new Closer(client);
		sr.setCloseHandlers(cch, sch);
		sr.run();
	}

	private Socket layerSsl(Socket socket, InetSocketAddress target)
			throws IOException {
		if (contextSelector == null) {
			throw new IllegalStateException(
					"SSL Context Selector is null, SSL is not supported!");
		}
		SSLContext sslContext = contextSelector.select(target);
		SSLSocketFactory factory = sslContext.getSocketFactory();
		SSLSocket sslsocket = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		// sslsocket.setEnabledProtocols(enabledProtocols);
		sslsocket.setUseClientMode(true);
		// sslsocket.setSoTimeout(soTimeout);
		sslsocket.startHandshake();
		return sslsocket;
	}

	private static class Closer implements Runnable {

		private Socket socket;

		public Closer(Socket socket) {
			this.socket = socket;
		}

		public void run() {
			try {
				if (!socket.isOutputShutdown()
						&& !(socket instanceof SSLSocket))
					socket.shutdownOutput();
			} catch (IOException e) {
				try {
					if (!socket.isOutputShutdown())
						socket.close();
				} catch (IOException ignore) {
				}
			}
		}
	}
}
