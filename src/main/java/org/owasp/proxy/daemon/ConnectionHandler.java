package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.Socket;

/**
 * Simple interface for classes that want to handle TCP connections, but don't
 * want to care about the details of listening for them.
 * 
 * @author rogan
 * 
 */
public interface ConnectionHandler {

	void handleConnection(Socket socket) throws IOException;

}
