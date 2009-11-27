package org.owasp.proxy.ssl;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;

/**
 * Simple interface for classes that want to handle potentially encrypted
 * connections, but don't want to bother with the details of the encryption.
 * 
 * @author rogan
 * 
 */
public interface EncryptedConnectionHandler {

	void handleConnection(Socket socket, InetSocketAddress target, boolean ssl)
			throws IOException;

}
