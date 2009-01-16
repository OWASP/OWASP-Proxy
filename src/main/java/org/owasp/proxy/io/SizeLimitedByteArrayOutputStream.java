package org.owasp.proxy.io;

import java.io.ByteArrayOutputStream;

public class SizeLimitedByteArrayOutputStream extends ByteArrayOutputStream {

	private int max;

	private boolean overflow = false;

	public SizeLimitedByteArrayOutputStream() {
		this(Integer.MAX_VALUE);
	}

	public SizeLimitedByteArrayOutputStream(int max) {
		super();
		this.max = max;
	}

	@Override
	public synchronized void reset() {
		super.reset();
		overflow = false;
	}

	@Override
	public synchronized void write(byte[] b, int off, int len) {
		if (!overflow) {
			if (size() + len > max) {
				len = max - size();
				overflow = true;
			}
			try {
				super.write(b, off, len);
			} catch (OutOfMemoryError oome) {
				overflow = true;
				super.buf = new byte[0];
				super.count = 0;
			}
		}
	}

	@Override
	public synchronized void write(int b) {
		if (!overflow && size() >= max) {
			overflow = true;
		} else
			try {
				super.write(b);
			} catch (OutOfMemoryError oome) {
				overflow = true;
				super.buf = new byte[0];
				super.count = 0;
			}
	}

	public boolean hasOverflowed() {
		return overflow;
	}

}
