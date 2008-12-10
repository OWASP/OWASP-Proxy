package org.owasp.webscarab.io;

import java.io.FilterInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * 
 * @author Rogan Dawes
 */
public class ChunkedInputStream extends FilterInputStream {
	
	private byte[] chunk = null;
	
	private int start = 0;
	
	private int size = 0;

	public ChunkedInputStream(InputStream in) throws IOException {
		super(in);
		readChunk();
	}

	private void readChunk() throws IOException {
		String line = readLine().trim();
		try {
			int semi = line.indexOf(';');
			if (semi > -1)
				line = line.substring(0, semi).trim();
			size = Integer.parseInt(line.trim(), 16);
			if (chunk == null || size > chunk.length)
				chunk = new byte[size];
			int read = 0;
			while (read < size) {
				int got = in.read(chunk, read, size - read);
				if (got > 0) {
					read = read + got;
				} else if (read == 0) {
				} else {
					continue;
				}
			}
			if (size == 0) { // read the trailer and the CRLF
				discardTrailer();
			} else {
				readLine(); // read the trailing line feed after the chunk body,
							// but before the next chunk size
			}
			start = 0;
		} catch (NumberFormatException nfe) {
			IOException ioe = new IOException("Error parsing chunk size from '" + line);
			ioe.initCause(nfe);
			throw ioe;
		}
	}

	public int read() throws IOException {
		if (size == 0) {
			return -1;
		}
		if (start == size) {
			readChunk();
		}
		if (size == 0) {
			return -1;
		}
		return chunk[start++];
	}

	public int read(byte[] b) throws IOException {
		return read(b, 0, b.length);
	}

	public int read(byte[] b, int off, int len) throws IOException {
		if (size == 0) {
			return -1;
		}
		if (start == size) {
			readChunk();
		}
		if (size == 0) {
			return -1;
		}
		if (len > available())
			len = available();
		System.arraycopy(chunk, start, b, off, len);
		start += len;
		return len;
	}

	public int available() throws IOException {
		return size - start;
	}

	public boolean markSupported() {
		return false;
	}

	private String readLine() throws IOException {
		StringBuilder line = new StringBuilder();
		int i = in.read();
		while (i > -1 && i != 10 && i != 13) {
			line = line.append((char) (i & 0xFF));
			i = in.read();
		}
		if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if
						// we got 13
			i = in.read();
			if (i != 10)
				throw new IOException("Unexpected character "
						+ Integer.toHexString(i) + ", was expecting 0x0A");
		}
		return line.toString();
	}

	/**
	 * This actually discards the trailer, since it is available for use via the
	 * raw content, if desired
	 * 
	 * @throws IOException
	 */
	private void discardTrailer() throws IOException {
		for (String line = readLine(); !"".equals(line); line = readLine())
			;
	}
}
