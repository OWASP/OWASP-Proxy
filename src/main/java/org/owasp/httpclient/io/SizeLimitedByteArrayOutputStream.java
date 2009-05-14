package org.owasp.httpclient.io;

import java.io.ByteArrayOutputStream;

public abstract class SizeLimitedByteArrayOutputStream extends
		ByteArrayOutputStream {

	private int max;

	public SizeLimitedByteArrayOutputStream(int max) {
		super();
		this.max = max;
	}

	public SizeLimitedByteArrayOutputStream(int size, int max) {
		super(size);
		this.max = max;
	}

	@Override
	public void write(int b) {
		if (count < max) {
			super.write(b);
			if (count >= max)
				overflow();
		}
	}

	@Override
	public void write(byte[] b, int off, int len) {
		if (count < max) {
			len = Math.min(max - count, len);
			super.write(b, off, len);
			if (count >= max)
				overflow();
		}
	}

	protected abstract void overflow();

}
