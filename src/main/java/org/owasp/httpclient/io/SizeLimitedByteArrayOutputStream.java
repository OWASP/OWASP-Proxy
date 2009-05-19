package org.owasp.httpclient.io;

import java.io.ByteArrayOutputStream;

public class SizeLimitedByteArrayOutputStream extends ByteArrayOutputStream {

	private int max;

	private boolean hardLimit = true;

	public SizeLimitedByteArrayOutputStream(int max) {
		super();
		this.max = max;
	}

	public SizeLimitedByteArrayOutputStream(int max, boolean hardLimit) {
		super();
		this.max = max;
		this.hardLimit = hardLimit;
	}

	public SizeLimitedByteArrayOutputStream(int size, int max) {
		super(size);
		this.max = max;
	}

	public SizeLimitedByteArrayOutputStream(int size, int max, boolean hardLimit) {
		super(size);
		this.max = max;
		this.hardLimit = hardLimit;
	}

	@Override
	public void write(int b) throws SizeLimitExceededException {
		if (count < max || !hardLimit) {
			super.write(b);
			if (count >= max)
				overflow();
		}
	}

	@Override
	public void write(byte[] b, int off, int len) throws SizeLimitExceededException {
		if (count < max || !hardLimit) {
			if (hardLimit)
				len = Math.min(max - count, len);
			super.write(b, off, len);
			if (count >= max)
				overflow();
		}
	}

	protected void overflow() {
		throw new SizeLimitExceededException(count + ">=" + max);
	}
}
