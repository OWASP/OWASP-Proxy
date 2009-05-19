package org.owasp.proxy.daemon;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.net.InetAddress;

import org.owasp.httpclient.BufferedRequest;
import org.owasp.httpclient.BufferedResponse;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.SizeLimitExceededException;
import org.owasp.httpclient.util.MessageUtils;

public class BufferingHttpRequestHandler implements HttpRequestHandler {

	private HttpRequestHandler next;

	private int max = 0;

	private boolean decode = false;

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

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	public StreamingResponse handleRequest(InetAddress source,
			StreamingRequest request) throws IOException,
			MessageFormatException {
		boolean decode = this.decode;
		BufferedRequest brq = new BufferedRequest.Impl();
		try {
			if (decode)
				request.setContent(MessageUtils.decode(request));
			MessageUtils.buffer(request, brq, max);
			brq = processRequest(brq);
			request = MessageUtils.stream(brq);
			if (decode)
				request.setContent(MessageUtils.encode(request));
		} catch (SizeLimitExceededException slee) {
			requestContentSizeExceeded(brq);
			InputStream buffered = new ByteArrayInputStream(brq.getContent());
			InputStream content = request.getContent();
			content = new SequenceInputStream(buffered, content);
			request.setContent(content);
			if (decode)
				request.setContent(MessageUtils.encode(request));
		}
		StreamingResponse response = next.handleRequest(source, request);
		if (bufferResponse(brq, response)) {
			BufferedResponse brs = new BufferedResponse.Impl();
			try {
				if (decode)
					response.setContent(MessageUtils.decode(response));
				MessageUtils.buffer(response, brs, max);
				brs = processResponse(brq, brs);
				response = MessageUtils.stream(brs);
				if (decode)
					response.setContent(MessageUtils.encode(response));
			} catch (SizeLimitExceededException slee) {
				responseContentSizeExceeded(brq, brs);
				InputStream buffered = new ByteArrayInputStream(brs
						.getContent());
				InputStream content = response.getContent();
				content = new SequenceInputStream(buffered, content);
				response.setContent(content);
				if (decode)
					response.setContent(MessageUtils.encode(response));
			}
		}
		return response;
	}

	protected boolean bufferResponse(BufferedRequest request,
			ResponseHeader response) {
		return true;
	}

	protected BufferedRequest processRequest(BufferedRequest request) {
		return request;
	}

	protected BufferedResponse processResponse(BufferedRequest request,
			BufferedResponse response) {
		return response;
	}

	protected void requestContentSizeExceeded(RequestHeader request) {
	}

	protected void responseContentSizeExceeded(RequestHeader request,
			ResponseHeader response) {
	}

}
