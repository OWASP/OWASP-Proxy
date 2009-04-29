package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * This class implements a Proxy server. The user is required to provide an
 * implementation of {@link TargetedConnectionHandler} implementing the desired
 * protocol.
 * 
 * The major difference between {@link Server} and Proxy is that Proxy may have
 * a target address. i.e. connections received by the Proxy should be directed
 * to the specified target.
 * 
 * @author Rogan Dawes
 * 
 */
public class Proxy extends Server {

	public Proxy(InetSocketAddress listen,
			final TargetedConnectionHandler connectionHandler,
			final InetSocketAddress target) throws IOException {
		super(listen, connectionHandler == null ? null
				: new ConnectionHandler() {

					/*
					 * (non-Javadoc)
					 * 
					 * @see
					 * org.owasp.proxy.daemon.ConnectionHandler#handleConnection
					 * (java .net.Socket)
					 */
					public void handleConnection(Socket socket)
							throws IOException {
						connectionHandler.handleConnection(socket, target);
					}

				});
	}
}
