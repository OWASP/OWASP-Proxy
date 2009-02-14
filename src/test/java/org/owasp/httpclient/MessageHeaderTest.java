/*
 *  This file is part of the OWASP Proxy, a free intercepting HTTP proxy
 *  library.
 *  Copyright (C) 2008  Rogan Dawes <rogan@dawes.za.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
/**
 * 
 */
package org.owasp.httpclient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import org.junit.Before;
import org.junit.Test;
import org.owasp.httpclient.util.AsciiString;

/**
 * @author Rogan Dawes
 * 
 */
public class MessageHeaderTest {

	private String CRLF = "\r\n";

	private String CRLFCRLF = CRLF + CRLF;

	private String get = "GET / HTTP/1.0";

	private String get3 = "GET / HTTP/1.0\r\nHost: localhost\r\nCookie: a=b";

	private String post = "POST / HTTP1.0\r\nHost: localhost\r\nCookie: a=b\r\nContent-Length: 10";

	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * Test method for {@link org.owasp.httpclient.Message#getMessage()}.
	 */
	@Test
	public void testGetSetHeader() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(get + CRLFCRLF));
		String s = AsciiString.create(m.getHeader());
		assertEquals(get + CRLFCRLF, s);
	}

	/**
	 * Test method for {@link org.owasp.httpclient.Message#getStartLine()}.
	 */
	@Test
	public void testGetFirstLine() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(get + CRLFCRLF));
		assertEquals(get, m.getStartLine());
		m.setHeader(AsciiString.getBytes(get3 + CRLFCRLF));
		assertEquals(get, m.getStartLine());
	}

	/**
	 * Test method for
	 * {@link org.owasp.httpclient.Message#setStartLine(java.lang.String)}.
	 */
	@Test
	public void testSetFirstLine() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setStartLine(get);
		assertEquals(get + CRLFCRLF, AsciiString.create(m.getHeader()));
	}

	/**
	 * Test method for {@link org.owasp.httpclient.Message#getHeaders()}.
	 */
	@Test
	public void testGetHeaders() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(post + CRLFCRLF));
		assertEquals(post, m.getStartLine() + CRLF
				+ NamedValue.join(m.getHeaders(), CRLF));
	}

	/**
	 * Test method for
	 * {@link org.owasp.httpclient.Message#setHeaders(org.owasp.httpclient.NamedValue[])}
	 * .
	 */
	@Test
	public void testSetHeaders() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		String first = post.substring(0, post.indexOf(CRLF));
		NamedValue[] h = NamedValue.parse(post.substring(first.length()
				+ CRLF.length()), CRLF, " *: *");
		try {
			m.setHeaders(h);
			fail("Should have thrown an exception here");
		} catch (MessageFormatException mfe) {
			// expected
			m.setHeader(null);
		}
		m.setStartLine(first);
		m.setHeaders(h);
		assertEquals(post + CRLFCRLF, AsciiString.create(m.getHeader()));
	}

	/**
	 * Test method for
	 * {@link org.owasp.httpclient.Message#getHeader(java.lang.String)}.
	 */
	@Test
	public void testGetHeaderString() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(post + CRLFCRLF));
		assertEquals("a=b", m.getHeader("cookie"));
	}

	/**
	 * Test method for
	 * {@link org.owasp.httpclient.Message#setHeader(java.lang.String, java.lang.String)}
	 * .
	 */
	@Test
	public void testSetHeaderStringString() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(post + CRLFCRLF));
		m.setHeader("Cookie", "a=c");
		assertEquals("a=c", m.getHeader("cookie"));
	}

	/**
	 * Test method for
	 * {@link org.owasp.httpclient.Message#addHeader(java.lang.String, java.lang.String)}
	 * .
	 */
	@Test
	public void testAddHeader() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(post + CRLFCRLF));
		m.addHeader("Cookie", "b=c");
		NamedValue[] headers = m.getHeaders();
		boolean found = false;
		for (int i = 0; i < headers.length; i++)
			if ("cookie".equalsIgnoreCase(headers[i].getName())
					&& "a=b".equals(headers[i].getValue()))
				found = true;
		assertTrue(found);
		found = false;
		for (int i = 0; i < headers.length; i++)
			if ("cookie".equalsIgnoreCase(headers[i].getName())
					&& "b=c".equals(headers[i].getValue()))
				found = true;
		assertTrue(found);
	}

	/**
	 * Test method for
	 * {@link org.owasp.httpclient.Message#deleteHeader(java.lang.String)}.
	 */
	@Test
	public void testDeleteHeader() throws Exception {
		MessageHeader m = new MessageHeader.Impl();
		m.setHeader(AsciiString.getBytes(post + CRLFCRLF));
		assertEquals("a=b", m.getHeader("Cookie"));
		m.deleteHeader("cookie");
		assertEquals(null, m.getHeader("cookie"));
	}

}
