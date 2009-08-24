package org.owasp.proxy.daemon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;

import org.owasp.proxy.daemon.BufferedMessageInterceptor.Action;
import org.owasp.proxy.httpclient.MessageFormatException;
import org.owasp.proxy.httpclient.MutableBufferedRequest;
import org.owasp.proxy.httpclient.MutableBufferedResponse;
import org.owasp.proxy.httpclient.RequestHeader;
import org.owasp.proxy.httpclient.StreamingRequest;
import org.owasp.proxy.httpclient.StreamingResponse;
import org.owasp.proxy.io.CountingInputStream;
import org.owasp.proxy.io.SizeLimitExceededException;
import org.owasp.proxy.util.AsciiString;
import org.owasp.proxy.util.MessageUtils;

public class BufferingHttpRequestHandler implements HttpRequestHandler {

	private static final byte[] CONTINUE = AsciiString
			.getBytes("HTTP/1.1 100 Continue\r\n\r\n");

	private final HttpRequestHandler next;

	protected int max = 0;

	protected boolean decode = false;

	private BufferedMessageInterceptor interceptor;

	public BufferingHttpRequestHandler(final HttpRequestHandler next,
			BufferedMessageInterceptor interceptor) {
		this.next = next;
		this.interceptor = interceptor;
	}

	public BufferingHttpRequestHandler(final HttpRequestHandler next,
			BufferedMessageInterceptor interceptor, final int max,
			final boolean decode) {
		this.next = next;
		this.interceptor = interceptor;
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
		final Action action = interceptor.directRequest(request);
		final MutableBufferedRequest brq;
		if (Action.BUFFER.equals(action)) {
			brq = new MutableBufferedRequest.Impl();
			try {
				if (decode) {
					request.setContent(MessageUtils.decode(request));
				}
				MessageUtils.buffer(request, brq, max);
				interceptor.processRequest(brq);
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
						interceptor.requestContentSizeExceeded(brq, getCount());
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
								interceptor.requestContentSizeExceeded(brq,
										size);
							} else {
								interceptor.requestStreamed(brq);
							}
						}
					});
		}
	}

	private void handleResponse(final RequestHeader request,
			final StreamingResponse response, boolean decode)
			throws IOException, MessageFormatException {
		Action action = interceptor.directResponse(request, response);
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
				interceptor.processResponse(request, brs);
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
						interceptor.responseContentSizeExceeded(request, brs,
								getCount());
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
								interceptor.responseContentSizeExceeded(
										request, brs, size);
							} else {
								interceptor.responseStreamed(request, brs);
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

}
