package org.owasp.proxy.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public class CountingInputStream extends FilterInputStream {

	int bytes = 0;

	public CountingInputStream(InputStream in) {
		super(in);
	}

	@Override
	public int read() throws IOException {
		int result = super.read();
		if (result == -1) {
			eof();
		} else {
			bytes++;
		}
		return result;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int result = super.read(b, off, len);
		if (result == -1) {
			eof();
		} else {
			bytes += result;
		}
		return result;
	}

	public int getCount() {
		return bytes;
	}

	protected void eof() {
	}
}
