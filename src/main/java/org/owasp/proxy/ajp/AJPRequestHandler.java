package org.owasp.proxy.ajp;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.proxy.httpclient.MessageFormatException;
import org.owasp.proxy.httpclient.StreamingResponse;

public interface AJPRequestHandler {

	StreamingResponse handleRequest(InetAddress source, AJPRequest request)
			throws IOException, MessageFormatException;

	void dispose() throws IOException;

}
