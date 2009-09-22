package org.owasp.proxy.httpclient;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.proxy.util.AsciiString;

public class MutableResponseHeaderTest {

	private static final String cont = "HTTP/1.0 100 Continue\r\n"
			+ "Header: Value\r\n" + "\r\n";
	private static final String ok = "HTTP/1.0 200 Ok\r\n"
			+ "Content-Type: text/html\r\n" + "\r\n";

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void test100Continue() throws Exception {
		MutableResponseHeader.Impl resp = new MutableResponseHeader.Impl();
		resp.setHeader(AsciiString.getBytes(cont));
		Assert.assertFalse(resp.has100Continue());
		Assert.assertEquals("100", resp.getStatus());
		resp.setStatus("200");
		Assert.assertEquals("200", resp.getStatus());

		resp.setHeader(AsciiString.getBytes(cont + ok));
		Assert.assertTrue(resp.has100Continue());
		Assert.assertEquals("200", resp.getStatus());
		resp.setHeaderLines(new String[] { "HTTP/1.0 302 Moved",
				"Location: new location", "" });
		Assert.assertTrue(resp.has100Continue());
		Assert.assertEquals("new location", resp.getHeader("Location"));
		System.out.write(resp.getHeader());
	}
}
