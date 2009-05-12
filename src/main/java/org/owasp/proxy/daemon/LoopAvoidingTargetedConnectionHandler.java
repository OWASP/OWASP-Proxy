package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

public class LoopAvoidingTargetedConnectionHandler implements
		TargetedConnectionHandler {

	private ServerGroup serverGroup;

	private TargetedConnectionHandler next;

	public LoopAvoidingTargetedConnectionHandler(ServerGroup registry,
			TargetedConnectionHandler next) {
		this.serverGroup = registry;
		this.next = next;
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
		if (serverGroup.wouldAccept(target))
			throw new IOException("Loop detected! Target " + target
					+ " is handled by a local server");
		next.handleConnection(socket, target);
	}

}
