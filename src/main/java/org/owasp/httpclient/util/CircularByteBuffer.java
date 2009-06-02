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
				System.arraycopy(buff, 0, t, (buff.length - start), length
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
		copyToBuffer(pos, b, off, len);
		length = length + len;
	}

	public void push(byte i) {
		ensureCapacity(1);
		int pos = 0;
		if (length > 0) {
			pos = start - 1;
			if (pos < 0)
				pos += buff.length;
		}
		buff[pos] = i;
		start = pos;
		length++;
	}

	public void push(byte[] b) {
		push(b, 0, b.length);
	}

	public void push(byte[] b, int off, int len) {
		ensureCapacity(len);

		int pos = 0;
		if (length > 0) {
			pos = start - len;
			if (pos < 0)
				pos += buff.length;
		}
		copyToBuffer(pos, b, off, len);
		start = pos;
		length += len;
	}

	private void copyToBuffer(int pos, byte[] b, int off, int len) {
		int l = buff.length - pos;
		if (l >= len) { // there is enough space in one chunk
			System.arraycopy(b, off, buff, pos, len);
		} else { // we have to wrap around
			System.arraycopy(b, off, buff, pos, l);
			System.arraycopy(b, off + l, buff, 0, len - l);
		}
	}

	private void copyFromBuffer(byte[] b, int off, int len) {
		int l = Math.min(buff.length - start, len);
		System.arraycopy(buff, start, b, off, l);
		if (l != len)
			System.arraycopy(buff, 0, b, off + l, len - l);
	}

	public int remove() {
		if (length == 0)
			return -1;

		int i = buff[start] & 0xFF;
		start = (start + 1) % buff.length;
		length--;

		return i;
	}

	public int remove(byte[] b) {
		return remove(b, 0, b.length);
	}

	public int remove(byte[] b, int off, int len) {
		if (length == 0)
			return -1;

		int read = Math.min(len, length);

		copyFromBuffer(b, off, read);
		start = (start + read) % buff.length;
		length = length - read;

		return read;
	}
}
