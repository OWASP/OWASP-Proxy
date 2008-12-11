package org.owasp.proxy.io;

import static org.junit.Assert.*;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.owasp.proxy.io.ChunkedInputStream;
import org.owasp.proxy.io.ChunkedOutputStream;

public class ChunkedInputStreamTest {

	private InputStream is;
	private String sample = "F ; extension=value\r\n" + "123456789ABCDEF\r\n"
			+ "E\r\n" + "123456789ABCDE\r\n" + "D; extension=value\r\n"
			+ "123456789ABCD\r\n" + "0; extension=\"value\"\r\n" + "\r\n";
	private String result = "123456789ABCDEF" + "123456789ABCDE"
			+ "123456789ABCD";

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testRead() throws Exception {
		is = new ChunkedInputStream(new ByteArrayInputStream(sample.getBytes()));
		try {
			StringBuilder buff = new StringBuilder();
			int got;
			while ((got = is.read()) > -1)
				buff.append((char) got);
			assertEquals(result, buff.toString());
		} catch (IOException ioe) {
			fail("Exception unexpected!" + ioe);
			ioe.printStackTrace();
		}
	}

	@Test
	public void testReadByteArrayIntInt() throws Exception {
		is = new ChunkedInputStream(new ByteArrayInputStream(sample.getBytes()));
		try {
			StringBuilder buff = new StringBuilder();
			byte[] b = new byte[12];
			int got;
			while ((got = is.read(b, 2, 7)) > -1)
				buff.append(new String(b, 2, got));
			assertEquals(result, buff.toString());
		} catch (IOException ioe) {
			fail("Exception unexpected!" + ioe);
			ioe.printStackTrace();
		}
	}

	@Test
	public void testReadLargeStream() throws Exception {
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		ChunkedOutputStream out = new ChunkedOutputStream((baos));
		byte[] buff = new byte[1786]; // odd random number not a power of 2
		for (int c=0; c<5; c++) {
			for (int i=0; i<buff.length; i++) {
				buff[i] = (byte) ((c * buff.length + i) % 26 + 'A');
			}
			out.write(buff);
		}
		out.close();
		ByteArrayInputStream bais = new ByteArrayInputStream(baos.toByteArray());
		is = new ChunkedInputStream(bais);
		buff = new byte[1024]; // different size to previous
		int got;
		int total = 0;
		while ((got = is.read(buff)) > 0) {
			System.err.println("Read " + got + " bytes");
			// verify expectation
			for (int i=0; i<got; i++) {
				assertEquals("byte " + (total + i) + " different!", (total + i) % 26 + 'A', buff[i]);
			}
			total = total + got;
		}
	}
}
