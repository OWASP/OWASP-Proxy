package org.owasp.proxy.daemon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;

import org.owasp.httpclient.BufferedRequest;
import org.owasp.httpclient.BufferedResponse;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.ReadOnlyBufferedRequest;
import org.owasp.httpclient.ReadOnlyBufferedResponse;
import org.owasp.httpclient.ReadOnlyRequestHeader;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.SizeLimitExceededException;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.httpclient.util.MessageUtils;

public class BufferingHttpRequestHandler implements HttpRequestHandler {

	private static byte[] CONTINUE = AsciiString
			.getBytes("HTTP/1.1 100 Continue\r\n\r\n");

	public enum Action {
		BUFFER, STREAM, IGNORE
	};

	private HttpRequestHandler next;

	protected int max = 0;

	protected boolean decode = false;

	public BufferingHttpRequestHandler(HttpRequestHandler next) {
		this.next = next;
	}

	public BufferingHttpRequestHandler(HttpRequestHandler next, int max,
			boolean decode) {
		this.next = next;
		this.max = max;
		this.decode = decode;
	}

	public void setMaximumContentSize(int max) {
		this.max = max;
	}

	public void setDecode(boolean decode) {
		this.decode = decode;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.HttpRequestHandler#dispose()
	 */
	public void dispose() throws IOException {
		next.dispose();
	}

	private void handleRequest(StreamingRequest request, boolean decode)
			throws IOException, MessageFormatException {
		Action action = directRequest(request);
		final BufferedRequest brq;
		switch (action) {
		case BUFFER:
			brq = new BufferedRequest.Impl();
			try {
				if (decode)
					request.setContent(MessageUtils.decode(request));
				MessageUtils.buffer(request, brq, max);
				processRequest(brq);
				MessageUtils.stream(brq, request);
				if (decode)
					request.setContent(MessageUtils.encode(request));
			} catch (SizeLimitExceededException slee) {
				requestContentSizeExceeded(brq);
				InputStream buffered = new ByteArrayInputStream(brq
						.getContent());
				InputStream content = request.getContent();
				content = new SequenceInputStream(buffered, content);
				request.setContent(content);
				if (decode)
					request.setContent(MessageUtils.encode(request));
			}
			break;
		case STREAM:
			brq = new BufferedRequest.Impl();
			MessageUtils.delayedCopy(request, brq, max,
					new MessageUtils.DelayedCopyObserver() {
						boolean overflow = false;

						@Override
						public void contentOverflow() {
							requestContentSizeExceeded(brq);
							overflow = true;
						}

						@Override
						public void copyCompleted() {
							if (!overflow)
								requestStreamed(brq);
						}
					});
		}
	}

	private void handleResponse(final ReadOnlyRequestHeader request,
			final StreamingResponse response, boolean decode)
			throws IOException, MessageFormatException {
		Action action = directResponse(request, response);
		final BufferedResponse brs;
		switch (action) {
		case BUFFER:
			brs = new BufferedResponse.Impl();
			try {
				if (decode) {
					try {
						response.setContent(MessageUtils.decode(response));
					} catch (MessageFormatException mfe) {
						throw new MessageFormatException(
								"Error decoding response for "
										+ request.getTarget()
										+ request.getResource(), mfe);
					} catch (IOException ioe) {
						IOException e = new IOException(
								"Error decoding response for "
										+ request.getTarget()
										+ request.getResource());
						e.initCause(ioe);
						throw e;
					}
				}
				MessageUtils.buffer(response, brs, max);
				processResponse(request, brs);
				MessageUtils.stream(brs, response);
				if (decode)
					response.setContent(MessageUtils.encode(response));
			} catch (SizeLimitExceededException slee) {
				responseContentSizeExceeded(request, brs);
				InputStream buffered = new ByteArrayInputStream(brs
						.getContent());
				InputStream content = response.getContent();
				content = new SequenceInputStream(buffered, content);
				response.setContent(content);
				if (decode)
					response.setContent(MessageUtils.encode(response));
			}
			break;
		case STREAM:
			brs = new BufferedResponse.Impl();
			MessageUtils.delayedCopy(response, brs, max,
					new MessageUtils.DelayedCopyObserver() {
						private boolean overflow = false;

						@Override
						public void contentOverflow() {
							responseContentSizeExceeded(request, brs);
							overflow = true;
						}

						@Override
						public void copyCompleted() {
							if (!overflow)
								responseStreamed(request, brs);
						}

					});
			break;
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	final public StreamingResponse handleRequest(InetAddress source,
			StreamingRequest request, boolean isContinue) throws IOException,
			MessageFormatException {
		boolean decode = this.decode;
		if (!isContinue && isExpectContinue(request))
			return get100Continue();

		handleRequest(request, decode);
		isContinue = false;

		StreamingResponse response = null;
		if (isExpectContinue(request)) {
			StreamingRequest cont = new StreamingRequest.Impl(request);
			response = next.handleRequest(source, cont, false);
			isContinue = isContinue(response);
			if (!isContinue)
				return response;
		}
		response = next.handleRequest(source, request, isContinue);
		handleResponse(request, response, decode);
		return response;
	}

	private boolean isExpectContinue(StreamingRequest request)
			throws MessageFormatException {
		return "continue".equalsIgnoreCase(request.getHeader("Expect"));
	}

	private boolean isContinue(StreamingResponse response)
			throws MessageFormatException {
		return "100".equals(response.getStatus());
	}

	private StreamingResponse get100Continue() {
		StreamingResponse response = new StreamingResponse.Impl();
		response.setHeader(CONTINUE);
		return response;
	}

	/**
	 * Called to determine what to do with the request. Implementations can
	 * choose to buffer the request to allow for modification, stream the
	 * request directly to the server, or ignore the request entirely.
	 * 
	 * Note that even if the request is ignored,
	 * {@link #directResponse(RequestHeader, ResponseHeader)} will still be
	 * called.
	 * 
	 * @param request
	 *            the request
	 * @return the desired Action
	 */
	protected Action directRequest(RequestHeader request) {
		return Action.BUFFER;
	}

	/**
	 * Called if the return value from {@link #directRequest(RequestHeader)} is
	 * BUFFER, once the request has been completely buffered. The request may be
	 * modified within this method. This method will not be called if the
	 * message content is larger than max bytes.
	 * 
	 * @param request
	 *            the request
	 */
	protected void processRequest(BufferedRequest request) {
	}

	/**
	 * Called if the return value from {@link #directRequest(RequestHeader)} is
	 * BUFFER or STREAM, and the request body is larger than the maximum message
	 * body specified
	 * 
	 * @param request
	 *            the request, containing max bytes of partial content
	 */
	protected void requestContentSizeExceeded(ReadOnlyBufferedRequest request) {
	}

	/**
	 * Called if the return value from {@link #directRequest(RequestHeader)} was
	 * STREAM, once the request has been completely sent to the server, and
	 * buffered. This method will not be called if the message content is larger
	 * than max bytes.
	 * 
	 * @param request
	 */
	protected void requestStreamed(ReadOnlyBufferedRequest request) {
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
	protected Action directResponse(ReadOnlyRequestHeader request,
			ResponseHeader response) {
		return Action.STREAM;
	}

	/**
	 * Called if the return value from
	 * {@link #directResponse(RequestHeader, ResponseHeader)} is BUFFER, once
	 * the response has been completely buffered. The response may be modified
	 * within this method. This method will not be called if the message content
	 * is larger than max bytes.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 */
	protected void processResponse(ReadOnlyRequestHeader request,
			BufferedResponse response) {
	}

	/**
	 * Called if the return value from
	 * {@link #directResponse(RequestHeader, ResponseHeader)} is BUFFER or
	 * STREAM, and the response body is larger than the maximum message body
	 * specified
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response, containing max bytes of partial content
	 */
	protected void responseContentSizeExceeded(ReadOnlyRequestHeader request,
			ReadOnlyBufferedResponse response) {
	}

	/**
	 * Called if the return value from
	 * {@link #directResponse(RequestHeader, ResponseHeader)} was STREAM, once
	 * the response has been completely sent to the client, and buffered. This
	 * method will not be called if the message content is larger than max
	 * bytes.
	 * 
	 * @param request
	 *            the request
	 * @param response
	 *            the response
	 */
	protected void responseStreamed(ReadOnlyRequestHeader request,
			ReadOnlyBufferedResponse response) {
	}

}
