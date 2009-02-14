package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;

public class DefaultProxyMonitor implements ProxyMonitor {

	public Response errorReadingRequest(Request request, Exception e) {
		// TODO Auto-generated method stub
		return null;
	}

	public Response errorReadingResponse(Request request,
			ResponseHeader header, Exception e) {
		// TODO Auto-generated method stub
		return null;
	}

	public Response requestReceived(Request request) {
		try {
			String connection = request.getHeader("Connection");
			String version = request.getVersion();
			if ("HTTP/1.1".equals(version) && connection != null) {
				String[] headers = connection.split(" *, *");
				for (int i = 0; i < headers.length; i++) {
					request.deleteHeader(headers[i]);
				}
			}
			request.deleteHeader("Proxy-Connection");
		} catch (MessageFormatException mfe) {
			mfe.printStackTrace();
		}
		return null;
	}

	public void requestSent(Request request) {
	}

	public void responseReceived(Request request, ResponseHeader header,
			InputStream responseContent, OutputStream client) {
		try {
			client.write(header.getHeader());
			byte[] buff = new byte[1024];
			int got;
			while ((got = responseContent.read(buff)) > -1)
				client.write(buff, 0, got);
			client.flush();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
	}

}
