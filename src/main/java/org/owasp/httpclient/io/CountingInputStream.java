package org.owasp.httpclient.io;

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
		if (result != -1)
			bytes++;
		return result;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int result = super.read(b, off, len);
		if (result != -1)
			bytes += result;
		return result;
	}

	public int getCount() {
		return bytes;
	}
}
