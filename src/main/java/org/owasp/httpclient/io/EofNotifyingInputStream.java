package org.owasp.httpclient.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

public abstract class EofNotifyingInputStream extends FilterInputStream {

	public EofNotifyingInputStream(InputStream in) {
		super(in);
	}

	protected abstract void eof();

	@Override
	public int read() throws IOException {
		int result = super.read();
		if (result == -1)
			eof();
		return result;
	}

	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int result = super.read(b, off, len);
		if (result == -1)
			eof();
		return result;
	}

}
