package org.owasp.proxy.tcp;

import java.io.IOException;
import java.io.OutputStream;

/**
 * Represents the worker that is reading data from the source socket, and
 * writing data to the destination socket.
 * 
 * It is used to link calls to the various {@link StreamInterceptor} methods
 * together. It also allows the {@link StreamInterceptor} implementation to
 * write intercepted data to the destination when appropriate, and close the
 * output stream when done.
 * 
 * @author rogan
 * 
 */
public interface StreamHandle {

	/**
	 * Writes the provided data to the destination
	 * 
	 * @see OutputStream#write(byte[], int, int)
	 */
	void write(byte[] b, int off, int len) throws IOException;

	/**
	 * Close the connection to the destination.
	 */
	void close();

}
