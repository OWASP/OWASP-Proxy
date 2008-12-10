/**
 * 
 */
package org.owasp.webscarab.model;

import static org.junit.Assert.*;

import org.junit.Before;
import org.junit.Test;

/**
 * @author Rogan Dawes
 *
 */
public class MessageTest {

	private String get = "GET / HTTP/1.0";
	private String get3 = "GET / HTTP/1.0\r\nHost: localhost\r\nCookie: a=b";
	private String post = "POST / HTTP1.0\r\nHost: localhost\r\nCookie: a=b\r\nContent-Length: 10";
	String content = "1234567890";

	private String CRLF = "\r\n";
	private String CRLFCRLF = CRLF + CRLF;
	
	/**
	 * @throws java.lang.Exception
	 */
	@Before
	public void setUp() throws Exception {
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getMessage()}.
	 */
	@Test
	public void testGetSetMessage() throws Exception {
		Message m = new Message();
		m.setMessage((get+CRLFCRLF).getBytes("ASCII"));
		String s = new String(m.getMessage(), "ASCII");
		assertEquals(get+CRLFCRLF, s);
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setMessage(byte[], byte[], byte[])}.
	 */
	@Test
	public void testSetMessageByteArrayByteArrayByteArray() throws Exception {
		Message m = new Message();
		m.setMessage(post.getBytes("ASCII"), CRLFCRLF.getBytes("ASCII"), content.getBytes("ASCII"));
		assertEquals(post + CRLFCRLF + content, new String(m.getMessage(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getHeader()}.
	 */
	@Test
	public void testGetHeader() throws Exception {
		Message m = new Message();
		m.setMessage((post + CRLFCRLF + content).getBytes("ASCII"));
		assertEquals(post, new String(m.getHeader(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setHeader(byte[])}.
	 */
	@Test
	public void testSetHeaderByteArray() throws Exception {
		Message m = new Message();
		m.setHeader(get.getBytes("ASCII"));
		assertEquals(get + CRLFCRLF, new String(m.getMessage(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getContent()}.
	 */
	@Test
	public void testGetContent() throws Exception {
		Message m = new Message();
		m.setMessage((post + CRLFCRLF + content).getBytes("ASCII"));
		assertEquals(content, new String(m.getContent(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setContent(byte[])}.
	 */
	@Test
	public void testSetContent() throws Exception {
		Message m = new Message();
		m.setHeader(post.getBytes("ASCII"));
		m.setContent(content.getBytes("ASCII"));
		assertEquals(post + CRLFCRLF + content, new String(m.getMessage(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getHeaderLines(byte[])}.
	 */
	@Test
	public void testGetHeaderLines() throws Exception {
		Message m = new Message();
		m.setMessage((post + CRLFCRLF + content).getBytes("ASCII"));
		String[] lines = m.getHeaderLines(CRLF.getBytes("ASCII"));
		StringBuilder b = new StringBuilder();
		for (int i=0; i<lines.length; i++) {
			b.append(lines[i]);
			if (i < lines.length - 1)
				b.append(CRLF);
		}
		assertEquals(post, b.toString());
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setHeaderLines(java.lang.String[], byte[])}.
	 */
	@Test
	public void testSetHeaderLines() throws Exception {
		String[] lines = get3.split("CRLF");
		Message m = new Message();
		m.setHeaderLines(lines, CRLF.getBytes("ASCII"));
		assertEquals(get3, new String(m.getHeader(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getStartLine()}.
	 */
	@Test
	public void testGetFirstLine() throws Exception {
		Message m = new Message();
		m.setHeader(get.getBytes("ASCII"));
		assertEquals(get, m.getStartLine());
		m = new Message();
		m.setHeader(get3.getBytes("ASCII"));
		assertEquals(get, m.getStartLine());
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setStartLine(java.lang.String)}.
	 */
	@Test
	public void testSetFirstLine() throws Exception {
		Message m = new Message();
		m.setStartLine(get);
		assertEquals(get, new String(m.getHeader(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getHeaders()}.
	 */
	@Test
	public void testGetHeaders() throws Exception {
		Message m = new Message();
		m.setHeader(post.getBytes("ASCII"));
		assertEquals(post, m.getStartLine() + CRLF + NamedValue.join(m.getHeaders(), CRLF));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setHeaders(org.owasp.webscarab.model.NamedValue[])}.
	 */
	@Test
	public void testSetHeaders() throws Exception {
		Message m = new Message();
		String first = post.substring(0, post.indexOf(CRLF));
		NamedValue[] h = NamedValue.parse(post.substring(first.length() + CRLF.length()), CRLF, " *: *");
		try {
			m.setHeaders(h);
			fail("Should have thrown an exception here");
		} catch (MessageFormatException mfe) {
			// expected
			m = new Message();
		}
		m.setStartLine(first);
		m.setHeaders(h);
		assertEquals(post, new String(m.getHeader(), "ASCII"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#getHeader(java.lang.String)}.
	 */
	@Test
	public void testGetHeaderString() throws Exception {
		Message m = new Message();
		m.setHeader(post.getBytes("ASCII"));
		assertEquals("a=b", m.getHeader("Cookie"));
		assertEquals("a=b", m.getHeader("cookie"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#setHeader(java.lang.String, java.lang.String)}.
	 */
	@Test
	public void testSetHeaderStringString() throws Exception {
		Message m = new Message();
		m.setHeader(post.getBytes("ASCII"));
		m.setHeader("Cookie", "a=c");
		assertEquals("a=c", m.getHeader("cookie"));
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#addHeader(java.lang.String, java.lang.String)}.
	 */
	@Test
	public void testAddHeader() throws Exception {
		Message m = new Message();
		m.setHeader(post.getBytes("ASCII"));
		m.addHeader("Cookie", "b=c");
		NamedValue[] headers = m.getHeaders();
		boolean found = false;
		for (int i=0;i<headers.length; i++)
			if ("cookie".equalsIgnoreCase(headers[i].getName()) && "a=b".equals(headers[i].getValue())) 
				found = true;
		assertTrue(found);
		found = false;
		for (int i=0;i<headers.length; i++)
			if ("cookie".equalsIgnoreCase(headers[i].getName()) && "b=c".equals(headers[i].getValue())) 
				found = true;
		assertTrue(found);
	}

	/**
	 * Test method for {@link org.owasp.webscarab.model.Message#deleteHeader(java.lang.String)}.
	 */
	@Test
	public void testDeleteHeader() throws Exception {
		Message m = new Message();
		m.setHeader(post.getBytes("ASCII"));
		assertEquals("a=b", m.getHeader("Cookie"));
		m.deleteHeader("cookie");
		assertEquals(null, m.getHeader("cookie"));
	}

}
