package org.owasp.proxy.daemon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;

import org.owasp.httpclient.BufferedRequest;
import org.owasp.httpclient.BufferedResponse;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MutableBufferedRequest;
import org.owasp.httpclient.MutableBufferedResponse;
import org.owasp.httpclient.MutableRequestHeader;
import org.owasp.httpclient.MutableResponseHeader;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.CountingInputStream;
import org.owasp.httpclient.io.SizeLimitExceededException;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.httpclient.util.MessageUtils;

public class BufferingHttpRequestHandler implements HttpRequestHandler {

	private static final byte[] CONTINUE = AsciiString
			.getBytes("HTTP/1.1 100 Continue\r\n\r\n");

	public enum Action {
		BUFFER, STREAM, IGNORE
	};

	private final HttpRequestHandler next;

	protected int max = 0;

	protected boolean decode = false;

	public BufferingHttpRequestHandler(final HttpRequestHandler next) {
		this.next = next;
	}

	public BufferingHttpRequestHandler(final HttpRequestHandler next,
			final int max, final boolean decode) {
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
	public final void dispose() throws IOException {
		next.dispose();
	}

	private void handleRequest(StreamingRequest request, final boolean decode)
			throws IOException, MessageFormatException {
		final Action action = directRequest(request);
		final MutableBufferedRequest brq;
		if (Action.BUFFER.equals(action)) {
			brq = new MutableBufferedRequest.Impl();
			try {
				if (decode) {
					request.setContent(MessageUtils.decode(request));
				}
				MessageUtils.buffer(request, brq, max);
				processRequest(brq);
				MessageUtils.stream(brq, request);
				if (decode) {
					request.setContent(MessageUtils.encode(request));
				}
			} catch (SizeLimitExceededException slee) {
				final InputStream buffered = new ByteArrayInputStream(brq
						.getContent());
				InputStream content = request.getContent();
				content = new SequenceInputStream(buffered, content);
				content = new CountingInputStream(content) {
					protected void eof() {
						requestContentSizeExceeded(brq, getCount());
					}
				};
				request.setContent(content);

				if (decode) {
					request.setContent(MessageUtils.encode(request));
				}
			}
		} else if (Action.STREAM.equals(action)) {
			brq = new MutableBufferedRequest.Impl();
			MessageUtils.delayedCopy(request, brq, max,
					new MessageUtils.DelayedCopyObserver() {
						@Override
						public void copyCompleted(boolean overflow, int size) {
							if (overflow) {
								requestContentSizeExceeded(brq, size);
							} else {
								requestStreamed(brq);
							}
						}
					});
		}
	}

	private void handleResponse(final RequestHeader request,
			final StreamingResponse response, boolean decode)
			throws IOException, MessageFormatException {
		Action action = directResponse(request, response);
		final MutableBufferedResponse brs;
		if (Action.BUFFER.equals(action)) {
			brs = new MutableBufferedResponse.Impl();
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
				if (decode) {
					response.setContent(MessageUtils.encode(response));
				}
			} catch (SizeLimitExceededException slee) {
				InputStream buffered = new ByteArrayInputStream(brs
						.getContent());
				InputStream content = response.getContent();
				content = new SequenceInputStream(buffered, content);
				content = new CountingInputStream(content) {
					protected void eof() {
						responseContentSizeExceeded(request, brs, getCount());
					}
				};
				response.setContent(content);
				if (decode) {
					response.setContent(MessageUtils.encode(response));
				}
			}
		} else if (Action.STREAM.equals(action)) {
			brs = new MutableBufferedResponse.Impl();
			MessageUtils.delayedCopy(response, brs, max,
					new MessageUtils.DelayedCopyObserver() {
						@Override
						public void copyCompleted(boolean overflow, int size) {
							if (overflow) {
								responseContentSizeExceeded(request, brs, size);
							} else {
								responseStreamed(request, brs);
							}
						}

					});
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	final public StreamingResponse handleRequest(final InetAddress source,
			final StreamingRequest request, boolean isContinue)
			throws IOException, MessageFormatException {
		boolean decode = this.decode;
		if (!isContinue && isExpectContinue(request)) {
			return get100Continue();
		}

		handleRequest(request, decode);
		isContinue = false;

		StreamingResponse response = null;
		if (isExpectContinue(request)) {
			StreamingRequest cont = new StreamingRequest.Impl(request);
			response = next.handleRequest(source, cont, false);
			isContinue = isContinue(response);
			if (!isContinue) {
				return response;
			}
		}
		response = next.handleRequest(source, request, isContinue);
		handleResponse(request, response, decode);
		return response;
	}

	private boolean isExpectContinue(final RequestHeader request)
			throws MessageFormatException {
		return "100-continue".equalsIgnoreCase(request.getHeader("Expect"));
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
	 * {@link #directResponse(MutableRequestHeader, MutableResponseHeader)} will
	 * still be called.
	 * 
	 * @param request
	 *            the request
	 * @return the desired Action
	 */
	protected Action directRequest(final MutableRequestHeader request) {
		return Action.BUFFER;
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
	protected void processRequest(final MutableBufferedRequest request) {
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
	protected void requestContentSizeExceeded(final BufferedRequest request,
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
	protected void requestStreamed(final BufferedRequest request) {
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
	protected Action directResponse(final RequestHeader request,
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
	protected void processResponse(final RequestHeader request,
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
	protected void responseContentSizeExceeded(final RequestHeader request,
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
	protected void responseStreamed(final RequestHeader request,
			final BufferedResponse response) {
	}

}
