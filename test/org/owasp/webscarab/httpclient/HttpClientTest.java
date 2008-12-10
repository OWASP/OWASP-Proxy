package org.owasp.webscarab.httpclient;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.webscarab.io.ChunkedInputStream;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.test.TraceServer;

public class HttpClientTest {

	private static TraceServer ts = null;
	
	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.err.println("Running setupBeforeClass()");
		ts = new TraceServer(9999);
		Thread t = new Thread(ts);
		t.setDaemon(false);
		t.start();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.err.println("Running shutdown after class");
		ts.stop();
		Thread.sleep(1000);
		assertTrue("TraceServer shutdown failed!", ts.isStopped());
	}

//	@Test
	public void testFetchResponse() throws Exception {
		HttpClient client = new HttpClient();
		Request request = new Request();
		request.setMessage("GET http://localhost:9999/blah/blah?abc=def HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes());
		Conversation c = client.fetchResponse(request);
		System.out.println("Headers: " + (c.getResponseHeaderTime() - c.getRequestTime()));
		System.out.println("Content: " + (c.getResponseBodyTime() - c.getResponseHeaderTime()));
		System.out.write(c.getResponse().getMessage());
	}

	@Test
	public void testChunked() throws Exception {
		HttpClient client = new HttpClient();
		Request request = new Request();
		request.setStartLine("GET http://www.google.co.za/search?q=webscarab&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a HTTP/1.1");
		request.addHeader("Host", "www.google.co.za");
		Conversation c = client.fetchResponse(request);
		System.out.println("Headers: " + (c.getResponseHeaderTime() - c.getRequestTime()));
		System.out.println("Content: " + (c.getResponseBodyTime() - c.getResponseHeaderTime()));
//		System.out.write(c.getResponse().getMessage());
//		System.out.print("<-The end");
		
		InputStream in = new ChunkedInputStream(new ByteArrayInputStream(c.getResponse().getContent()));
		byte[] buff = new byte[1024];
		int got;
		while ((got = in.read(buff)) > 0) {
			System.out.write(buff, 0, got);
		}
	}
}
