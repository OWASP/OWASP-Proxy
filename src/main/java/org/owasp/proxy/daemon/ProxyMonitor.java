package org.owasp.proxy.daemon;

import java.io.InputStream;
import java.io.OutputStream;

import org.owasp.httpclient.Request;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;

public interface ProxyMonitor {

	/**
	 * Called when the complete request has been read from the server.
	 * 
	 * @param request
	 *            the request
	 * @return a Response to be returned immediately to the client, or null
	 */
	Response requestReceived(Request request);

	/**
	 * called in the event of an exception while reading the request
	 * 
	 * @param request
	 *            contains any bytes which have been read from the client
	 * @param e
	 *            the exception which was encountered
	 * @return a custom response to be sent to the client, or null for the
	 *         default error response
	 */
	Response errorReadingRequest(Request request, Exception e);

	void requestSent(Request request);

	/**
	 * called when the response header has been read from the server.
	 * Implementations are responsible for writing the response header to the
	 * provided OutputStream, and copying any content read from the InputStream
	 * to the provided OutputStream
	 * 
	 * @param request
	 *            the request that resulted in this response
	 * @param header
	 *            the response headers read from the server
	 * @param responseContent
	 *            an InputStream from which the response content (if any) can be
	 *            read. If there is no response content to be read, the
	 *            InputStream will return EOF immediately
	 * @param client
	 *            an OutputStream connected to the client
	 */
	void responseReceived(Request request, ResponseHeader header,
			InputStream responseContent, OutputStream client);

	/**
	 * called in the event of an exception while reading the response headers
	 * 
	 * @param request
	 *            the request which was sent to the server
	 * @param header
	 *            any bytes read before the exception
	 * @param e
	 *            the exception which was encountered
	 * @return a custom response to be sent to the client, or null for the
	 *         default error response
	 */
	Response errorReadingResponse(Request request, ResponseHeader header,
			Exception e);

}
