package org.owasp.ajp;

import java.io.IOException;
import java.net.InetAddress;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.proxy.daemon.HttpRequestHandler;

public class AJPHttpRequestHandlerAdapter implements AJPRequestHandler {

	private HttpRequestHandler handler;

	public AJPHttpRequestHandlerAdapter(HttpRequestHandler handler) {
		this.handler = handler;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.ajp.AJPRequestHandler#dispose()
	 */
	public void dispose() throws IOException {
		handler.dispose();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.ajp.AJPRequestHandler#handleRequest(java.net.InetAddress,
	 * org.owasp.ajp.AJPRequest)
	 */
	public StreamingResponse handleRequest(InetAddress source,
			AJPRequest request) throws IOException, MessageFormatException {
		return handler.handleRequest(source, request, false);
	}

}
