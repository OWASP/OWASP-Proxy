package org.owasp.proxy.daemon;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.owasp.httpclient.BufferedRequest;
import org.owasp.httpclient.BufferedResponse;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MutableBufferedMessage;
import org.owasp.httpclient.MutableBufferedRequest;
import org.owasp.httpclient.MutableBufferedResponse;
import org.owasp.httpclient.MutableRequestHeader;
import org.owasp.httpclient.MutableResponseHeader;
import org.owasp.httpclient.NamedValue;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.util.AsciiString;
import org.owasp.httpclient.util.MessageUtils;
import org.owasp.proxy.test.TraceServer;

public class BufferingHttpRequestHandlerTest {

	private static Mock mock = new Mock();

	private static TraceServer ts = null;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		ts = new TraceServer(9999);
		Thread t = new Thread(ts);
		t.setDaemon(false);
		t.start();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		ts.stop();
		Thread.sleep(1000);
		assertTrue("TraceServer shutdown failed!", ts.isStopped());
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testOnline() throws Exception {
		StreamingRequest request = new StreamingRequest.Impl();
		request.setTarget(new InetSocketAddress("ajax.googleapis.com", 443));
		request.setSsl(true);
		request
				.setHeader(AsciiString
						.getBytes("GET /ajax/libs/jquery/1.3.2/jquery.min.js HTTP/1.1\r\n"
								+ "User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_6; en-us) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1\r\n"
								+ "Cache-Control: max-age=0\r\n"
								+ "Referer: http://freshmeat.net/\r\n"
								+ "Accept: */*\r\n"
								+ "Accept-Language: en-us\r\n"
								+ "Accept-Encoding: gzip, deflate\r\n"
								+ "Connection: keep-alive\r\n"
								+ "Host: ajax.googleapis.com\r\n\r\n"));
		HttpRequestHandler rh = new DefaultHttpRequestHandler();
		StreamingResponse response = rh.handleRequest(null, request, false);
		MutableBufferedResponse brs = new MutableBufferedResponse.Impl();
		MessageUtils.buffer(response, brs, Integer.MAX_VALUE);
		byte[] content = MessageUtils.decode(brs);
		MessageDigest digest = MessageDigest.getInstance("MD5");
		digest.update(content);
		byte[] d = digest.digest();
		System.out.print("Digest: ");
		for (int i = 0; i < d.length; i++) {
			System.out.print(Integer.toHexString((d[i] & 0xFF)) + " ");
		}
		// System.out.write(content);

		request
				.setHeader(AsciiString
						.getBytes("GET /favicon.ico HTTP/1.1\r\n"
								+ "User-Agent: Mozilla/5.0 (Macintosh; U; Intel Mac OS X 10_5_6; en-us) AppleWebKit/525.27.1 (KHTML, like Gecko) Version/3.2.1 Safari/525.27.1\r\n"
								+ "Cache-Control: max-age=0\r\n"
								+ "Referer: http://freshmeat.net/\r\n"
								+ "Accept: */*\r\n"
								+ "Accept-Language: en-us\r\n"
								+ "Accept-Encoding: gzip, deflate\r\n"
								+ "Connection: keep-alive\r\n"
								+ "Host: ajax.googleapis.com\r\n\r\n"));

		response = rh.handleRequest(null, request, false);
		brs = new MutableBufferedResponse.Impl();
		MessageUtils.buffer(response, brs, Integer.MAX_VALUE);
		content = MessageUtils.decode(brs);
		// System.out.write(content);

		//
		// byte[] buff = new byte[1024];
		// int got;
		//
		// InputStream in;
		// in = new FileInputStream("/Users/rogan/tmp/unchunked");
		// in = new ChunkedInputStream(in);
		// ByteArrayOutputStream chunked = new ByteArrayOutputStream();
		// in = new CopyInputStream(in, chunked);
		// // in = new FileInputStream("/Users/rogan/tmp/op");
		// try {
		// in = new GunzipInputStream(in);
		// while ((got = in.read(buff)) > -1)
		// System.out.println("Got " + got);
		// } catch (IOException ioe) {
		// ioe.printStackTrace();
		// }
		// in = new FileInputStream("/Users/rogan/tmp/op");
		// ByteArrayOutputStream unchunked = new ByteArrayOutputStream();
		// in = new CopyInputStream(in, unchunked);
		// try {
		// in = new GunzipInputStream(in);
		// while ((got = in.read(buff)) > -1)
		// System.out.println("Got " + got);
		// } catch (IOException ioe) {
		// ioe.printStackTrace();
		// }
		// byte[] chunkedBytes = chunked.toByteArray();
		// byte[] unchunkedBytes = unchunked.toByteArray();
		// System.out.println("Chunked = " + chunkedBytes.length +
		// " unchunked = "
		// + unchunkedBytes.length);
		// for (int i = 0; i < Math
		// .min(chunkedBytes.length, unchunkedBytes.length); i++) {
		// if (chunkedBytes[i] != unchunkedBytes[i])
		// System.out.println(i + ": unchunked: " + unchunkedBytes[i]
		// + " chunked: " + chunkedBytes[i]);
		// }
		//
	}

	@Test
	public void testContinue() throws Exception {
		HttpRequestHandler rh = new DefaultHttpRequestHandler();
		rh = new LoggingHttpRequestHandler(rh);
		rh = new BufferingHttpRequestHandler(rh, 1024, false);

		StreamingRequest req = new StreamingRequest.Impl();
		req.setTarget(new InetSocketAddress("localhost", 9999));
		req.setSsl(false);
		req
				.setHeader(AsciiString
						.getBytes("POST /target HTTP/1.1\r\n"
								+ "Host: localhost\r\nContent-Length: 20\r\nExpect: continue\r\n\r\n"));
		byte[] content = AsciiString.getBytes("01234567890123456789");
		StreamingResponse resp = rh.handleRequest(req.getTarget().getAddress(),
				req, false);
		assertEquals("Expected continue", "100", resp.getStatus());
		req = new StreamingRequest.Impl(req);
		req.setContent(new ByteArrayInputStream(content));
		resp = rh.handleRequest(req.getTarget().getAddress(), req, true);
		assertEquals("Expected OK", "200", resp.getStatus());
		InputStream rc = resp.getContent();
		assertTrue("Content is encorrect!", Arrays.equals(content, toArray(rc)));
	}

	private byte[] toArray(InputStream in) throws IOException {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buff = new byte[1024];
		int got;
		while ((got = in.read(buff)) > -1)
			baos.write(buff, 0, got);
		in.close();
		return baos.toByteArray();
	}

	@Test
	@Ignore
	public void testHandleRequest() throws Exception {
		BufferMock bm = new BufferMock(mock);
		bm.setDecode(true);
		bm.setMaximumContentSize(65536);
		test(bm, false, false, 32768);
		test(bm, true, true, 32768);
	}

	private void test(BufferMock bm, boolean chunked, boolean gzipped, int size)
			throws Exception {
		MutableBufferedRequest brq = createRequest("/?chunked=" + chunked
				+ "&gzipped=" + gzipped + "&size=" + size, size);
		StreamingRequest srq = new StreamingRequest.Impl();
		MessageUtils.stream(brq, srq);

		StreamingResponse srs = bm.handleRequest(null, srq, false);

		MutableBufferedResponse brs = new MutableBufferedResponse.Impl();
		MessageUtils.buffer(srs, brs, Integer.MAX_VALUE);

		compare(brq, bm.result.request);
		compare(brs, bm.result.response);
	}

	private void compare(MutableBufferedMessage a, MutableBufferedMessage b) {
		assertTrue(Arrays.equals(a.getHeader(), b.getHeader()));
		if (!(a.getContent() == b.getContent() && a.getContent() == null)) {
			assertTrue(Arrays.equals(a.getContent(), b.getContent()));
		}
	}

	private MutableBufferedRequest createRequest(String resource, int size)
			throws MessageFormatException {
		MutableBufferedRequest request = new MutableBufferedRequest.Impl();
		request.setStartLine("POST " + resource + " HTTP/1.1");
		request.setHeader("Content-Length", Integer.toString(size));
		byte[] content = new byte[size];
		fill(content);
		request.setContent(content);
		return request;
	}

	private static void fill(byte[] a) {
		for (int i = 0; i < a.length; i++) {
			a[i] = (byte) (i % 256);
		}
	}

	private static class Result {
		public MutableBufferedRequest request = null;
		public MutableBufferedResponse response = null;
		public boolean requestOverflow = false;
		public boolean responseOverflow = false;

		public void reset() {
			request = null;
			response = null;
			requestOverflow = false;
			responseOverflow = false;
		}
	}

	private static class BufferMock extends BufferingHttpRequestHandler {

		private Result result = new Result();

		public BufferMock(HttpRequestHandler next) {
			super(next);
		}

		@Override
		protected Action directRequest(MutableRequestHeader request) {
			return Action.BUFFER;
		}

		@Override
		protected Action directResponse(RequestHeader request,
				MutableResponseHeader response) {
			return Action.BUFFER;
		}

		@Override
		protected void processRequest(MutableBufferedRequest request) {
			result.request = request;
		}

		@Override
		protected void processResponse(RequestHeader request,
				MutableBufferedResponse response) {
			result.response = response;
		}

		@Override
		protected void requestContentSizeExceeded(BufferedRequest request) {
			result.requestOverflow = true;
		}

		@Override
		protected void responseContentSizeExceeded(RequestHeader request,
				BufferedResponse response) {
			result.responseOverflow = true;
		}

	}

	private static class Mock implements HttpRequestHandler {

		private static Logger logger = Logger.getAnonymousLogger();

		public void dispose() throws IOException {
			logger.info("Dispose called");
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.owasp.proxy.daemon.HttpRequestHandler#handleRequest(java.net.
		 * InetAddress, org.owasp.httpclient.StreamingRequest)
		 */
		public StreamingResponse handleRequest(InetAddress source,
				StreamingRequest request, boolean isContinue)
				throws IOException, MessageFormatException {
			boolean chunked = false;
			boolean gzipped = false;
			int size = 16384;
			try {
				String resource = request.getResource();
				int q = resource.indexOf('?');
				String query = q > -1 ? resource.substring(q + 1) : null;
				NamedValue[] nv = NamedValue.parse(query, "&", "=");
				chunked = "true".equals(NamedValue.findValue(nv, "chunked"));
				gzipped = "true".equals(NamedValue.findValue(nv, "chunked"));
				String s = NamedValue.findValue(nv, "size");
				if (s != null) {
					try {
						size = Integer.parseInt(s);
					} catch (NumberFormatException nfe) {
						logger.info("Invalid message size");
					}
				}
				byte[] content = new byte[size];
				fill(content);
				StreamingResponse response = new StreamingResponse.Impl();
				response.setStartLine("HTTP/1.0 200 Ok");
				if (chunked)
					response.setHeader("Transfer-Encoding", "chunked");
				if (gzipped)
					response.setHeader("Content-Encoding", "gzip");
				response.setContent(new ByteArrayInputStream(content));
				response.setContent(MessageUtils.encode(response));
				logger.info("Response (" + (chunked ? "chunked" : "unchunked")
						+ "," + (gzipped ? "gzipped" : "unzipped")
						+ ") size = " + size);
				return response;
			} catch (MessageFormatException mfe) {
				return null;
			}
		}

	}

}
