package org.owasp.proxy.daemon;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

import org.owasp.httpclient.Request;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.Conversation;

public class BufferedProxyMonitorAdapter implements ProxyMonitor {

	private ThreadLocal<Conversation> conversation = new ThreadLocal<Conversation>();

	private BufferedProxyMonitor monitor;

	public BufferedProxyMonitorAdapter(BufferedProxyMonitor monitor) {
		this.monitor = monitor;
	}

	public Response errorReadingRequest(Request request, Exception e) {
		org.owasp.proxy.model.Request r = new org.owasp.proxy.model.Request();
		copy(request, r);
		Response response = monitor.errorReadingRequest(r, e);
		copy(r, request);
		return response;
	}

	public Response errorReadingResponse(org.owasp.httpclient.Request request,
			ResponseHeader header, Exception e) {
		org.owasp.proxy.model.Request r = new org.owasp.proxy.model.Request();
		copy(request, r);
		Response response = monitor.errorFetchingResponseHeader(r, e);
		copy(r, request);
		return response;
	}

	public Response requestReceived(Request request) {
		Conversation c = new Conversation();
		conversation.set(c);
		org.owasp.proxy.model.Request r = new org.owasp.proxy.model.Request();
		copy(request, r);
		Response response = monitor.requestReceived(r);
		copy(r, request);
		return response;
	}

	public void requestSent(Request request) {
		Conversation c = conversation.get();
		c.setRequestTime(System.currentTimeMillis());
	}

	public void responseReceived(Request request, ResponseHeader header,
			InputStream responseContent, OutputStream client)
			throws IOException {
		org.owasp.proxy.model.Request r = new org.owasp.proxy.model.Request();
		copy(request, r);
		Conversation c = conversation.get();
		c.setResponseHeaderTime(System.currentTimeMillis());
		c.setRequest(r);
		org.owasp.proxy.model.Response resp = new org.owasp.proxy.model.Response();
		resp.setHeader(header.getHeader());
		c.setResponse(resp);
		boolean stream = monitor.responseHeaderReceived(c);
		if (stream) {
			try {
				client.write(resp.getHeader());
				ByteArrayOutputStream copy = new ByteArrayOutputStream();
				OutputStream[] copies = new OutputStream[] { client, copy };
				CopyInputStream in = new CopyInputStream(responseContent,
						copies);
				byte[] buff = new byte[1024];
				while (in.read(buff) > -1)
					;
				resp.setContent(copy.toByteArray());
				c.setResponseContentTime(System.currentTimeMillis());
				monitor.wroteResponseToBrowser(c);
			} catch (IOException ioe) {
				monitor.errorFetchingResponseContent(c, ioe);
			}
		} else {
			ByteArrayOutputStream copy = new ByteArrayOutputStream();
			try {
				CopyInputStream in = new CopyInputStream(responseContent, copy);
				byte[] buff = new byte[1024];
				while (in.read(buff) > -1)
					;
				resp.setContent(copy.toByteArray());
				monitor.responseContentBuffered(c);
				c.setResponseContentTime(System.currentTimeMillis());
				try {
					client.write(resp.getHeader());
					client.write(resp.getContent());
				} catch (IOException ioe) {
					monitor.errorWritingResponseToBrowser(c, ioe);
				}
			} catch (IOException ioe) {
				monitor.errorFetchingResponseContent(c, ioe);
			}
			monitor.conversationCompleted(c);
		}
	}

	private void copy(Request a, Request b) {
		b.setHost(a.getHost());
		b.setPort(a.getPort());
		b.setSsl(a.isSsl());
		b.setHeader(a.getHeader());
		b.setContent(a.getContent());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ProxyMonitor#connectionFromClient(java.net.Socket)
	 */
	public void connectionFromClient(Socket socket) {
	}

}
