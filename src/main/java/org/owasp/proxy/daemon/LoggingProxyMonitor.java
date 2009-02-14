package org.owasp.proxy.daemon;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.PrintStream;

import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.Request;
import org.owasp.httpclient.Response;
import org.owasp.httpclient.ResponseHeader;

public class LoggingProxyMonitor extends DefaultProxyMonitor {

	@Override
	public Response errorReadingRequest(Request request, Exception e) {
		try {
			System.err.println("Error reading request: \n");
			if (request != null) {
				System.err.write(request.getHeader());
				if (request.getContent() != null)
					System.err.write(request.getContent());
			}
			e.printStackTrace(new PrintStream(System.err));
		} catch (IOException ioe) {
		}
		return null;

	}

	@Override
	public Response errorReadingResponse(Request request,
			ResponseHeader header, Exception e) {
		try {
			System.err.println("Error fetching response header: \n");
			System.err.write(request.getHeader());
			if (request.getContent() != null)
				System.err.write(request.getContent());
			e.printStackTrace(new PrintStream(System.err));
		} catch (IOException ioe) {
		}
		return null;
	}

	@Override
	public void responseReceived(Request request, ResponseHeader header,
			InputStream responseContent, OutputStream client) {
		try {
			long start = System.currentTimeMillis();

			CountingInputStream cis = new CountingInputStream(responseContent);
			super.responseReceived(request, header, cis, client);

			long time = System.currentTimeMillis() - start;
			if (time == 0)
				time = 1;
			int size = cis.getBytes();

			StringBuilder buff = new StringBuilder();
			buff.append(request.getMethod()).append(" ");
			buff.append(request.isSsl() ? "ssl " : "");
			buff.append(request.getHost()).append(":")
					.append(request.getPort());
			buff.append(request.getResource()).append(" ");
			buff.append(header.getStatus()).append(" - ").append(size);
			buff.append(" bytes in ").append(time).append("(").append(
					size / (time * 1000));
			buff.append(" bps)");
			System.out.println(buff.toString());
		} catch (MessageFormatException mfe) {
		}
	}

	private static class CountingInputStream extends FilterInputStream {

		int bytes = 0;

		public CountingInputStream(InputStream in) {
			super(in);
		}

		@Override
		public int read() throws IOException {
			int result = super.read();
			if (result != -1)
				bytes++;
			return result;
		}

		@Override
		public int read(byte[] b, int off, int len) throws IOException {
			int result = super.read(b, off, len);
			if (result != -1)
				bytes += result;
			return result;
		}

		public int getBytes() {
			return bytes;
		}
	}
}
