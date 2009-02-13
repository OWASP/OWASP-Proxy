package org.owasp.httpclient.util;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.util.Arrays;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

public class CircularByteBufferTest {

	private CircularByteBuffer cb = new CircularByteBuffer(16);

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
	public void addAndRemove() {
		cb.add((byte) 'A');
		cb.add((byte) 'B');
		cb.add((byte) 'C');
		assertEquals(3, cb.length());
		assertTrue(cb.remove() == (byte) 'A');
		assertTrue(cb.remove() == (byte) 'B');
		assertTrue(cb.remove() == (byte) 'C');
		String s = "DEFGHIJKLMNOPQRS";
		cb.add(s.getBytes(), 0, s.length());
		assertEquals(cb.length(), s.length());
		byte[] b = new byte[s.length()];
		int got = cb.remove(b, 0, b.length);
		assertEquals(got, s.length());
		assertEquals(new String(b), s);
		s = "TUVWXYZABCDEFGHIJKLMNOPQRS";
		cb.add(s.getBytes(), 0, s.length());
		assertEquals(cb.length(), s.length());
		b = new byte[s.length()];
		got = cb.remove(b, 0, b.length);
		assertEquals(got, s.length());
		assertEquals(new String(b), s);
	}

	@Test
	public void bigChunks() {
		String s16 = "ABCDEFGHIJKLMNOP";
		cb.add(s16.getBytes());
		assertEquals(s16.length(), cb.length());
		byte[] buff = new byte[cb.length()];
		int got = cb.remove(buff);
		assertEquals(s16.length(), got);
		assertTrue(Arrays.equals(s16.getBytes(), buff));

		cb.add((byte) 'Z');
		cb.add((byte) 'Z');
		cb.add((byte) 'Z');
		assertEquals((byte) 'Z', cb.remove());
		assertEquals((byte) 'Z', cb.remove());
		assertEquals((byte) 'Z', cb.remove());

		cb.add(s16.getBytes());
		assertEquals(s16.length(), cb.length());
		buff = new byte[cb.length()];
		got = cb.remove(buff);
		assertEquals(s16.length(), got);
		assertTrue(Arrays.equals(s16.getBytes(), buff));
	}
}
