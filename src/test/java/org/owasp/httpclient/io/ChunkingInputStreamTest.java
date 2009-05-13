package org.owasp.httpclient.io;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.logging.Logger;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Assert;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChunkingInputStreamTest {

	private static Logger logger = Logger.getAnonymousLogger();

	private byte[] data;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
	}

	@Before
	public void setUp() throws Exception {
	}

	@After
	public void tearDown() throws Exception {
	}

	@Test
	public void testRead() throws IOException {
		data = new byte[16385];
		for (int i = 0; i < data.length; i++)
			data[i] = (byte) (i % 256);
		InputStream is = new ByteArrayInputStream(data);
		is = new ChunkingInputStream(is);
		is = new ChunkedInputStream(is);
		byte[] buff = new byte[data.length + 1024];
		int read = 0, got;
		while ((got = is.read(buff, read, Math.min(1024, buff.length - read))) > -1) {
			logger.fine("Read " + got);
			read += got;
		}
		Assert.assertEquals(data.length, read);
		compare(data, 0, buff, 0, read);
	}

	private void compare(byte[] a, int ao, byte[] b, int bo, int len) {
		for (int i = 0; i < len; i++) {
			Assert.assertEquals("Unexpected input at position " + (ao + i)
					+ "/" + (bo + i), a[ao + i], b[bo + i]);
		}
	}

}
