package org.owasp.proxy.io;

import java.io.ByteArrayInputStream;
import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

import org.junit.Assert;
import org.junit.BeforeClass;
import org.junit.Test;

public class ChangeMonitorInputStreamTest {

	private static byte[] original;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		original = new byte[16384];
		for (int i = 0; i < original.length; i++) {
			original[i] = (byte) (i % 256);
		}
	}

	@Test
	public void testBasicCopy() throws Exception {
		InputStream in = new ByteArrayInputStream(original);
		ChangeMonitorInputStream cmis = new ChangeMonitorInputStream(in);
		in = cmis;
		int read = flush(in);
		Assert.assertEquals("Read the wrong number of bytes", original.length,
				read);
		compare(original, cmis.getOriginal());
	}

	@Test
	public void testSimpleWatch() throws Exception {
		InputStream in = new ByteArrayInputStream(original);
		ChangeMonitorInputStream cmis = new ChangeMonitorInputStream(in);
		in = cmis.watch(cmis, "No changes");
		int read = flush(in);
		Assert.assertEquals("Read the wrong number of bytes", original.length,
				read);
		compare(original, cmis.getOriginal());
		Assert.assertEquals("Unexpectd copy!", 0,
				cmis.getModifiedStreams().length);
	}

	@Test
	public void testChangingWatch() throws Exception {
		InputStream in = new ByteArrayInputStream(original);
		ChangeMonitorInputStream cmis = new ChangeMonitorInputStream(in);
		in = cmis;
		in = new ModuloInputStream(in, 16);
		in = cmis.watch(in, "Modulo 16");
		int read = flush(in);
		Assert.assertEquals("Read the wrong number of bytes", original.length,
				read);
		Assert.assertEquals("missing copy!", 1,
				cmis.getModifiedStreams().length);
		byte[] copy = cmis.getModifiedStreams()[0].toByteArray();
		for (int i = 0; i < original.length; i++)
			Assert.assertEquals("Incorrect modulo at " + i,
					(byte) ((original[i] % 16) & 0xFF), copy[i]);
	}

	private int flush(InputStream in) throws IOException {
		byte[] buff = new byte[767];
		int read = 0, got;
		// while (in.read() > -1)
		// read++;
		while ((got = in.read(buff)) > 0) {
			read += got;
			// for (int i = 0; i < 16; i++) {
			// if (in.read() > -1) {
			// read++;
			// } else {
			// break;
			// }
			// }
		}
		return read;
	}

	private void compare(byte[] src, byte[] dst) {
		Assert.assertEquals("lengths differ", src.length, dst.length);
		for (int i = 0; i < src.length; i++)
			Assert.assertEquals("Difference at " + i, src[i], dst[i]);
	}

	private static class ModuloInputStream extends FilterInputStream {
		private int modulo;

		public ModuloInputStream(InputStream in, int modulo) {
			super(in);
			this.modulo = modulo;
		}

		public int read() throws IOException {
			int ret = super.read();
			if (ret > 0)
				ret = (ret % modulo) & 0xFF;
			return ret;
		}

		public int read(byte[] b, int off, int len) throws IOException {
			int ret = super.read(b, off, len);
			if (ret > 0) {
				for (int i = off; i < off + len; i++)
					b[i] = (byte) (b[i] % modulo);
			}
			return ret;
		}
	}
}
