package org.owasp.proxy.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;
import java.util.logging.Level;
import java.util.logging.Logger;

public class ResettablePushbackInputStream extends PushbackInputStream {

	private Logger logger = Logger.getLogger(getClass().toString());

	private byte[] markBuffer = null;

	private int markPos = 0;

	private int eof = 0;

	public ResettablePushbackInputStream(InputStream is, int buffsize) {
		super(is, buffsize);
		logger.setLevel(Level.FINEST);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.PushbackInputStream#unread(byte[], int, int)
	 */
	@Override
	public void unread(byte[] b, int off, int len) throws IOException {
		if (markBuffer != null) {
			if (markPos >= len) {
				boolean same = true;
				int markStart = markPos - len;
				for (int i = 0; same && i < len; i++) {
					if (b[off + i] != markBuffer[markStart + i])
						same = false;
				}
				if (same) {
					markPos -= len;
				} else {
					markBuffer = null;
				}
			} else {
				markBuffer = null;
			}
		}
		super.unread(b, off, len);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.PushbackInputStream#unread(int)
	 */
	@Override
	public void unread(int i) throws IOException {
		if (markBuffer != null) {
			if (markPos > 0) {
				byte b = (byte) (i & 0xFF);
				if (markBuffer[markPos] == b) {
					markPos--;
				} else {
					markBuffer = null;
				}
			} else {
				markBuffer = null;
			}
		}
		super.unread(i);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.PushbackInputStream#mark(int)
	 */
	@Override
	public synchronized void mark(int readlimit) {
		if (markBuffer == null || markBuffer.length != readlimit)
			markBuffer = new byte[readlimit];
		markPos = 0;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.PushbackInputStream#markSupported()
	 */
	@Override
	public boolean markSupported() {
		return true;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.PushbackInputStream#reset()
	 */
	@Override
	public synchronized void reset() throws IOException {
		if (markBuffer == null)
			throw new IOException("Resetting to invalid mark");
		super.unread(markBuffer, 0, markPos);
		markBuffer = null;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#read()
	 */
	@Override
	public int read() throws IOException {
		logger.entering("", "read()");
		int i = super.read();
		if (i == -1) {
			if (eof > 100) {
				Exception e = new IOException("Repeated read after EOF");
				e.printStackTrace();
				System.exit(1);
			}
			eof++;
		}
		record(i);
		logger.exiting("", "read()", i);
		return i;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#read(byte[], int, int)
	 */
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		logger.entering(getClass().getName(), "read(b, off, len)");
		int i = super.read(b, off, len);
		record(b, off, i);
		logger.exiting(getClass().getName(), "read(b, off, len)", i);
		return i;
	}

	@Override
	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	private void record(int i) {
		if (markBuffer == null)
			return;
		if (markPos == markBuffer.length) {
			markBuffer = null;
			return;
		}
		markBuffer[markPos++] = (byte) (i & 0xFF);
	}

	private void record(byte[] buff, int offset, int len) {
		if (markBuffer == null)
			return;
		if (markPos + len >= markBuffer.length) {
			markBuffer = null;
			return;
		}
		System.arraycopy(buff, offset, markBuffer, markPos, len);
		markPos += len;
	}

}
