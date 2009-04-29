package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;

public interface HttpRequestHandler {

	StreamingResponse handleRequest(InetAddress source, StreamingRequest request)
			throws IOException, MessageFormatException;

	void dispose() throws IOException;

}
