package org.owasp.proxy.examples;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.CountingInputStream;
import org.owasp.httpclient.io.EofNotifyingInputStream;
import org.owasp.proxy.daemon.DefaultHttpProxy;

public class LoggingHttpProxy extends DefaultHttpProxy {

	public LoggingHttpProxy(InetSocketAddress listen, InetSocketAddress target,
			SOCKS socks, SSL ssl) throws IOException {
		super(listen, target, socks, ssl);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.DefaultHttpProxy#handleRequest(java.net.InetAddress
	 * , org.owasp.httpclient.StreamingRequest)
	 */
	@Override
	protected StreamingResponse handleRequest(final InetAddress source,
			final StreamingRequest request) throws IOException {
		final StreamingResponse response = super.handleRequest(source, request);
		InputStream content = response.getContent();
		if (content == null) {
			log(source, request, response, 0);
		} else {
			final CountingInputStream cis = new CountingInputStream(content);
			final EofNotifyingInputStream eofis = new EofNotifyingInputStream(
					cis) {
				public void eof() {
					log(source, request, response, cis.getCount());
				}
			};
			response.setContent(eofis);
		}
		return response;
	}

	private void log(InetAddress source, RequestHeader request,
			ResponseHeader response, int bytes) {
		try {
			StringBuilder buff = new StringBuilder();
			buff.append(source.getHostAddress()).append(" - - ");
			buff.append(System.currentTimeMillis()).append(" \"");
			buff.append(request.getMethod()).append(" ");
			buff.append(request.isSsl() ? "https" : "http").append("://");
			buff.append(request.getTarget().getHostName());
			buff.append(request.getResource()).append(" ");
			buff.append(request.getVersion()).append("\" ");
			buff.append(response.getStatus()).append(" ");
			buff.append(bytes);
			System.out.println(buff.toString());
		} catch (MessageFormatException ignore) {
		}
	}

}
