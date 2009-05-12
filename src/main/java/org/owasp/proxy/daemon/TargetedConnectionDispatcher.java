package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.util.HashMap;
import java.util.Map;
import java.util.logging.Logger;

import org.owasp.proxy.util.Pump;

public class TargetedConnectionDispatcher implements TargetedConnectionHandler {

	private static Logger logger = Logger
			.getLogger(TargetedConnectionDispatcher.class.getName());

	/**
	 * Simply relays bytes from one socket to the other, ignoring any upstream
	 * proxy settings
	 */
	public static final TargetedConnectionHandler RELAY = new TargetedConnectionHandler() {
		public void handleConnection(Socket src, InetSocketAddress target)
				throws IOException {
			logger.fine("Relaying from " + src.getRemoteSocketAddress()
					+ " to " + target);
			Socket dest = new Socket(Proxy.NO_PROXY);
			dest.connect(target);
			Pump.connect(src, dest);
		}
	};

	private Map<InetSocketAddress, TargetedConnectionHandler> handlers;

	private Map<Integer, TargetedConnectionHandler> ports;

	private TargetedConnectionHandler defaultHandler = RELAY;

	public TargetedConnectionDispatcher() {
		handlers = new HashMap<InetSocketAddress, TargetedConnectionHandler>();
		ports = new HashMap<Integer, TargetedConnectionHandler>();
	}

	public void addHandler(InetSocketAddress target,
			TargetedConnectionHandler handler) {
		handlers.put(target, handler);
	}

	public void addHandler(int port, TargetedConnectionHandler handler) {
		ports.put(port, handler);
	}

	public void setDefaultHandler(TargetedConnectionHandler defaultHandler) {
		this.defaultHandler = defaultHandler;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.TargetedConnectionHandler#handleConnection(java
	 * .net.Socket, java.net.InetSocketAddress)
	 */
	public void handleConnection(Socket socket, InetSocketAddress target)
			throws IOException {
		TargetedConnectionHandler handler = handlers.get(target);
		if (handler == null)
			handler = ports.get(target.getPort());
		if (handler == null)
			handler = defaultHandler;
		if (handler == null)
			return;
		handler.handleConnection(socket, target);
	}

}
