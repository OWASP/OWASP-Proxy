package org.owasp.proxy.ajp;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.proxy.http.MessageFormatException;
import org.owasp.proxy.http.StreamingResponse;

public interface AJPRequestHandler {

	StreamingResponse handleRequest(InetAddress source, AJPRequest request)
			throws IOException, MessageFormatException;

	void dispose() throws IOException;

}
