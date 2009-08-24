package org.owasp.proxy.daemon;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.proxy.httpclient.MessageFormatException;
import org.owasp.proxy.httpclient.StreamingRequest;
import org.owasp.proxy.httpclient.StreamingResponse;

public interface HttpRequestHandler {

	StreamingResponse handleRequest(InetAddress source, StreamingRequest request, boolean isContinue)
			throws IOException, MessageFormatException;

	void dispose() throws IOException;

}
