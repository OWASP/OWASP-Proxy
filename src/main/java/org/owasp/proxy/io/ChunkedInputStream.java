/*
 *  This file is part of the OWASP Proxy, a free intercepting HTTP proxy
 *  library.
 *  Copyright (C) 2008  Rogan Dawes <rogan@dawes.za.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
package org.owasp.proxy.io;

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
		String line = readLine();
		try {
			int semi = line.indexOf(';');
			if (semi > -1)
				line = line.substring(0, semi);
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
			if (size > 0) {
				// read the trailing line feed after the chunk body,
				// but before the next chunk size
				readCRLF();
			} else {
				chunk = null; // enable GC
				discardTrailer();
			}
			start = 0;
		} catch (NumberFormatException nfe) {
			IOException ioe = new IOException("Error parsing chunk size from '"
					+ line);
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

	/**
	 * Read the CRLF terminator.
	 * 
	 * @throws IOException
	 *             If an IO error occurs.
	 */
	private void readCRLF() throws IOException {
		int cr = in.read();
		int lf = in.read();
		if ((cr != '\r') || (lf != '\n')) {
			throw new IOException("CRLF expected at end of chunk: " + cr + "/"
					+ lf);
		}
	}

	private String readLine() throws IOException {
		StringBuilder line = new StringBuilder();
		int i = in.read();
		while (i > -1 && i != '\r' && i != '\n') {
			line = line.append((char) (i & 0xFF));
			i = in.read();
		}
		if (i == '\n') {
			throw new IOException("Unexpected LF, was expecting a CR first");
		} else if (i == '\r') {
			i = in.read();
			if (i != '\n')
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
		while (!"".equals(readLine()))
			System.err.println("t");
	}
}
