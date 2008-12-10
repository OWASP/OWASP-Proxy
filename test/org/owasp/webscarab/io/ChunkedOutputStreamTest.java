package org.owasp.webscarab.io;

import java.io.IOException;
import java.io.OutputStream;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

public class ChunkedOutputStreamTest {

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testWriteByteArrayIntInt() throws IOException {
		OutputStream out = new ChunkedOutputStream(System.out);
		out.write("ABCDEFGHIJKLMNOPQRSTUVWXYZ".getBytes());
		out.close();
	}

}
