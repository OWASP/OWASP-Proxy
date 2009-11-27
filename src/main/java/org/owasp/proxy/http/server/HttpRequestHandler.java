package org.owasp.proxy.http.server;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.proxy.http.MessageFormatException;
import org.owasp.proxy.http.StreamingRequest;
import org.owasp.proxy.http.StreamingResponse;

public interface HttpRequestHandler {

	StreamingResponse handleRequest(InetAddress source, StreamingRequest request, boolean isContinue)
			throws IOException, MessageFormatException;

	void dispose() throws IOException;

}
