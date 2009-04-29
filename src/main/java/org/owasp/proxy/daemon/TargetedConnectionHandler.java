package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * This interface allows implementations to be informed of the target address of
 * a connection.
 * 
 * The target may come either from a SOCKS proxy, or from a {@see Proxy} class
 * that has a hard-coded target i.e. a reverse-proxy.
 * 
 * @author rogan
 * 
 */
public interface TargetedConnectionHandler {

	void handleConnection(Socket socket, InetSocketAddress target)
			throws IOException;

}
