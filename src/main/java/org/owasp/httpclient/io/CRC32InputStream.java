package org.owasp.httpclient.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.zip.CRC32;

public class CRC32InputStream extends FilterInputStream {

	private CRC32 crc = new CRC32();

	public CRC32InputStream(InputStream in) {
		super(in);
	}

	public int read() throws IOException {
		int result = super.read();
		if (result > -1)
			crc.update(result);
		return result;
	}

	public int read(byte[] b, int off, int len) throws IOException {
		int got = super.read(b, off, len);
		if (got > 0)
			crc.update(b, off, got);
		return got;
	}

	public long getValue() {
		return crc.getValue();
	}

}
