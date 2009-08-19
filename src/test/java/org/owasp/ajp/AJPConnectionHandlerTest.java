package org.owasp.ajp;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MutableBufferedResponse;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.httpclient.util.MessageUtils;
import org.owasp.proxy.daemon.Server;

public class AJPConnectionHandlerTest {

	private static MutableBufferedResponse response;

	private static AJPRequestHandler handler = new AJPRequestHandler() {
		public void dispose() throws IOException {
		}

		public StreamingResponse handleRequest(InetAddress source,
				AJPRequest request) throws IOException, MessageFormatException {
			StreamingResponse resp = new StreamingResponse.Impl();
			System.out.println(request.toString());
			String cl = request.getHeader("Content-Length");
			if (cl != null) {
				int len = Integer.parseInt(cl);
				validatePayload(len, request.getContent());
				resp.setHeader(AsciiString
						.getBytes("HTTP/1.1 200 Ok\r\nContent-Length: " + cl
								+ "\r\n\r\n"));
				resp.setContent(generatePayload(len));
			} else {
				resp
						.setHeader(AsciiString
								.getBytes("HTTP/1.0 200 Ok\r\nContent-Length: 16\r\n\r\n"));
				resp.setContent(new ByteArrayInputStream(AsciiString
						.getBytes("0123456789ABCDEF")));
			}
			return resp;
		}

		private InputStream generatePayload(int size) {
			byte[] buff = new byte[size];
			for (int i = 0; i < size; i++)
				buff[i] = (byte) (i % 0xFF);
			return new ByteArrayInputStream(buff);
		}

		private void validatePayload(int size, InputStream in)
				throws IOException {
			if (in != null) {
				byte[] buff = new byte[1024];
				int got, read = 0;
				while ((got = in.read(buff)) > -1) {
					for (int i = 0; i < got; i++) {
						if (read + i < size
								&& buff[i] != (byte) ((read + i) % 0xFF)) {
							throw new RuntimeException("Error at " + (read + i)
									+ ": Expected "
									+ ((byte) ((read + i) % 0xFF)) + ", got "
									+ buff[i]);
						}
					}
					read += got;
				}
				if (read != size)
					throw new RuntimeException("Expected " + size + ", got "
							+ read);
			} else {
				if (size > 0) {
					throw new RuntimeException("Expected " + size
							+ ", got nothing at all");
				}
			}
		}

	};

	private static Server server;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		response = new MutableBufferedResponse.Impl();
		response.setHeader(AsciiString
				.getBytes("HTTP/1.1 200 Ok\r\nContent-Length: 16\r\n\r\n"));
		response.setContent(AsciiString.getBytes("0123456789ABCDEF"));
		AJPConnectionHandler ach = new AJPConnectionHandler(handler);
		server = new Server(new InetSocketAddress("localhost", 8009), ach);
		server.start();
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		server.stop();
	}

	@Test
	public void testHandleConnection() throws Exception {
		AJPClient client = new AJPClient(new InetSocketAddress("localhost",
				8009));

		StreamingRequest req = new StreamingRequest.Impl();
		req.setTarget(new InetSocketAddress("www.target.com", 443));
		req.setSsl(true);
		req.setHeader(AsciiString.getBytes("GET /test/?a=b HTTP/1.0\r\n"
				+ "Host: www.target.com\r\n\r\n"));

		StreamingResponse response = client.fetchResponse(req);

		MutableBufferedResponse resp = new MutableBufferedResponse.Impl();
		MessageUtils.buffer(response, resp, Integer.MAX_VALUE);
		System.out.println(resp);
	}

}
