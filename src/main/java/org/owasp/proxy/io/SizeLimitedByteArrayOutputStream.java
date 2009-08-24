package org.owasp.proxy.io;

import java.io.ByteArrayOutputStream;

public class SizeLimitedByteArrayOutputStream extends ByteArrayOutputStream {

	private int max;

	public SizeLimitedByteArrayOutputStream(int max) {
		super();
		if (max <= 0)
			throw new IllegalArgumentException("max cannot be zero or negative");
		this.max = max;
	}

	public SizeLimitedByteArrayOutputStream(int size, int max) {
		super(size);
		this.max = max;
	}

	@Override
	public void write(int b) throws SizeLimitExceededException {
		if (count < max) {
			super.write(b);
			if (count >= max)
				overflow();
		}
	}

	@Override
	public void write(byte[] b, int off, int len)
			throws SizeLimitExceededException {
		if (count < max) {
			super.write(b, off, len);
			if (count >= max)
				overflow();
		}
	}

	protected void overflow() {
		throw new SizeLimitExceededException(count + ">=" + max);
	}
}
