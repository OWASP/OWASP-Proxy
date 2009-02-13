package org.owasp.httpclient.util;

/**
 * This class implements a circular buffer that allows writing and reading to
 * the buffer. Note: It is not inherently thread safe!
 * 
 * The idea is that data may be added to the buffer, and later read from it. The
 * buffer will automatically grow to ensure capacity for the data added to it.
 * It does not currently shrink when the data is read from it.
 * 
 * @author rogan
 * 
 */
public class CircularByteBuffer {

	private byte[] buff;

	private int start = 0, length = 0;

	public CircularByteBuffer(int initialSize) {
		buff = new byte[initialSize];
	}

	public int length() {
		return length;
	}

	private void ensureCapacity(int bytes) {
		int avail = buff.length - length;
		if (avail < bytes) {
			byte[] t = new byte[buff.length * 2];
			if (length == 0) {
				// copy nothing
			} else if (start + length <= buff.length) {
				System.arraycopy(buff, start, t, 0, length);
			} else if (start + length > buff.length) {
				System.arraycopy(buff, start, t, 0, buff.length - start);
				System.arraycopy(buff, 0, t, start, length
						- (buff.length - start));
			}
			start = 0;
			buff = t;
		}
	}

	public void add(byte i) {
		ensureCapacity(1);
		buff[(start + length) % buff.length] = i;
		length++;
	}

	public void add(byte[] b) {
		add(b, 0, b.length);
	}

	public void add(byte[] b, int off, int len) {
		ensureCapacity(len);

		int pos = (start + length) % buff.length;
		int l = buff.length - pos;
		if (l >= len) { // there is enough space in one chunk
			System.arraycopy(b, off, buff, pos, len);
		} else { // we have to wrap around
			System.arraycopy(b, off, buff, pos, l);
			System.arraycopy(b, off + l, buff, 0, len - l);
		}
		length = length + len;
	}

	public byte remove() {
		byte b = buff[start];
		start = (start + 1) % buff.length;
		length--;
		// if (length == 0)
		// start = 0;
		return b;
	}

	public int remove(byte[] b) {
		return remove(b, 0, b.length);
	}

	public int remove(byte[] b, int off, int len) {
		int read = Math.min(len, length);

		int l = Math.min(buff.length - start, read);
		System.arraycopy(buff, start, b, off, l);
		start = (start + l) % buff.length;
		length = length - l;

		// if (length == 0)
		// start = 0;
		//
		if (l < read) {
			return l + remove(b, off + l, len - l);
		} else {
			return l;
		}
	}
}
