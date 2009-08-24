package org.owasp.proxy.daemon;

import org.owasp.proxy.httpclient.BufferedRequest;
import org.owasp.proxy.httpclient.BufferedResponse;
import org.owasp.proxy.httpclient.MutableBufferedRequest;
import org.owasp.proxy.httpclient.MutableBufferedResponse;
import org.owasp.proxy.httpclient.MutableRequestHeader;
import org.owasp.proxy.httpclient.MutableResponseHeader;
import org.owasp.proxy.httpclient.RequestHeader;
import org.owasp.proxy.httpclient.ResponseHeader;

public abstract class BufferedMessageInterceptor {

	public enum Action {
		BUFFER, STREAM, IGNORE
	};

	/**
	 * Called to determine what to do with the request. Implementations can
	 * choose to buffer the request to allow for modification, stream the
	 * request directly to the server while buffering the request for later
	 * review, or ignore the request entirely.
	 * 
	 * Note that even if the request is ignored,
	 * {@link #directResponse(MutableRequestHeader, MutableResponseHeader)} will
	 * still be called.
	 * 
	 * @param request
	 *            the request
	 * @return the desired Action
	 */
	public Action directRequest(final MutableRequestHeader request) {
		return Action.STREAM;
	}

	/**
	 * Called if the return value from
	 * {@link #directRequest(MutableRequestHeader)} is BUFFER, once the request
	 * has been completely buffered. The request may be modified within this
	 * method. This method will not be called if the message content is larger
	 * than max bytes.
	 * 
	 * @param request
	 *            the request
	 */
	public void processRequest(final MutableBufferedRequest request) {
	}

	/**
	 * Called if the return value from
	 * {@link #directRequest(MutableRequestHeader)} is BUFFER or STREAM, and the
	 * request body is larger than the maximum message body specified
	 * 
	 * @param request
	 *            the request, containing max bytes of partial content
	 * @param size
	 *            the ultimate size of the request content
	 */
	public void requestContentSizeExceeded(final BufferedRequest request,
			int size) {
	}

	/**
	 * Called if the return value from
	 * {@link #directRequest(MutableRequestHeader)} was STREAM, once the request
	 * has been completely sent to the server, and buffered. This method will
	 * not be called if the message content is larger than max bytes.
	 * 
	 * @param request
	 *            the request
	 */
	public void requestStreamed(final BufferedRequest request) {
	}

	/**
	 * Called to determine what to do with the response. Implementations can
	 * choose to buffer the response to allow for modification, stream the
	 * response directly to the client, or ignore the response entirely.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 * @return the desired Action
	 */
	public Action directResponse(final RequestHeader request,
			final MutableResponseHeader response) {
		return Action.STREAM;
	}

	/**
	 * Called if the return value from
	 * {@link #directResponse(MutableRequestHeader, MutableResponseHeader)} is
	 * BUFFER, once the response has been completely buffered. The response may
	 * be modified within this method. This method will not be called if the
	 * message content is larger than max bytes.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 */
	public void processResponse(final RequestHeader request,
			final MutableBufferedResponse response) {
	}

	/**
	 * Called if the return value from
	 * {@link #directResponse(MutableRequestHeader, MutableResponseHeader)} is
	 * BUFFER or STREAM, and the response body is larger than the maximum
	 * message body specified
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response, containing max bytes of partial content
	 * @param size
	 *            the eventual size of the response content
	 */
	public void responseContentSizeExceeded(final RequestHeader request,
			final ResponseHeader response, int size) {
	}

	/**
	 * Called if the return value from
	 * {@link #directResponse(MutableRequestHeader, MutableResponseHeader)} was
	 * STREAM, once the response has been completely sent to the client, and
	 * buffered. This method will not be called if the message content is larger
	 * than max bytes.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 */
	public void responseStreamed(final RequestHeader request,
			final BufferedResponse response) {
	}

}
