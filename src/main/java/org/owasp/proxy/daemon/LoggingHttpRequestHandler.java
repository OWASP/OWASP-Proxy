package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.CountingInputStream;
import org.owasp.httpclient.io.EofNotifyingInputStream;

public class LoggingHttpRequestHandler implements HttpRequestHandler {

	private PrintStream out;

	private HttpRequestHandler next;

	public LoggingHttpRequestHandler(HttpRequestHandler next) {
		this(System.out, next);
	}

	public LoggingHttpRequestHandler(PrintStream out, HttpRequestHandler next) {
		this.out = out;
		this.next = next;
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
	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.proxy.daemon.DefaultHttpRequestHandler#handleRequest
	 * (java.net.InetAddress, org.owasp.httpclient.StreamingRequest)
	 */
	public StreamingResponse handleRequest(final InetAddress source,
			final StreamingRequest request) throws IOException,
			MessageFormatException {
		final StreamingResponse response = next.handleRequest(source, request);
		if (response.getContent() != null) {
			final CountingInputStream cis = new CountingInputStream(response
					.getContent());
			final EofNotifyingInputStream eofis = new EofNotifyingInputStream(
					cis) {
				public void eof() {
					log(source, request, response, cis.getCount());
				}
			};
			response.setContent(eofis);
		} else {
			log(source, request, response, 0);
		}
		return response;
	}

	protected void log(InetAddress source, RequestHeader request,
			ResponseHeader response, int bytes) {
		try {
			StringBuilder buff = new StringBuilder();
			buff.append(source.getHostAddress()).append(" - - ");
			buff.append(System.currentTimeMillis()).append(" \"");
			buff.append(request.getMethod()).append(" ");
			buff.append(request.isSsl() ? "https://" : "http://");
			buff.append(request.getTarget().getHostName());
			buff.append(request.getResource()).append(" ");
			buff.append(request.getVersion()).append("\" ");
			buff.append(response.getStatus()).append(" ");
			buff.append(bytes);
			out.println(buff.toString());
		} catch (MessageFormatException ignore) {
		}
	}

}
