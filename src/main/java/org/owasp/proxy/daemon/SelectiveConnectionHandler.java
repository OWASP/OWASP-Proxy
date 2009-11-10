package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;

import org.owasp.proxy.util.Pump;

public abstract class SelectiveConnectionHandler implements
		TargetedConnectionHandler {

	/**
	 * Simply relays bytes from one socket to the other, ignoring any upstream
	 * proxy settings
	 */
	protected static final TargetedConnectionHandler RELAY = new TargetedConnectionHandler() {
		public void handleConnection(Socket src, InetSocketAddress target)
				throws IOException {
			Socket dest = new Socket(Proxy.NO_PROXY);
			dest.connect(target);
			Pump.connect(src, dest);
		}
	};

	public abstract TargetedConnectionHandler getConnectionHandler(
			InetSocketAddress target);

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.TargetedConnectionHandler#handleConnection(java
	 * .net.Socket, java.net.InetSocketAddress)
	 */
	public void handleConnection(Socket socket, InetSocketAddress target)
			throws IOException {
		TargetedConnectionHandler tch = getConnectionHandler(target);
		tch.handleConnection(socket, target);
	}

}
