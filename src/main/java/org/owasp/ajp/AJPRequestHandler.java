package org.owasp.ajp;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.StreamingResponse;

public interface AJPRequestHandler {

	StreamingResponse handleRequest(InetAddress source, AJPRequest request)
			throws IOException, MessageFormatException;

	void dispose() throws IOException;

}
