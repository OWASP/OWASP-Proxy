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
import java.io.OutputStream;

/**
 * CopyInputStream writes a copy of everything that is read through it to one or
 * more OutputStreams. This can be used to copy what is read from a
 * SocketInputStream to a SocketOutputStream, while keeping a copy of what was
 * read in a ByteArrayOutputStream, for example.
 * 
 * Any OutputStreams that throw Exceptions when being written to are not written
 * to again.
 * 
 * @author rogan
 * 
 */
public class CopyInputStream extends FilterInputStream {

	private OutputStream[] copy;

	public CopyInputStream(InputStream in, OutputStream copy) {
		this(in, new OutputStream[] { copy });
	}

	public CopyInputStream(InputStream in, OutputStream[] copy) {
		super(in);
		if (copy == null || copy.length == 0)
			throw new IllegalArgumentException("copy may not be null or empty");
		this.copy = new OutputStream[copy.length];
		System.arraycopy(copy, 0, this.copy, 0, copy.length);
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#markSupported()
	 */
	@Override
	public boolean markSupported() {
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#read()
	 */
	@Override
	public int read() throws IOException {
		int ret = super.read();
		if (ret > -1)
			for (int i = 0; i < copy.length; i++) {
				if (copy[i] == null)
					continue;
				try {
					copy[i].write(ret);
				} catch (IOException ioe) {
					copy[i] = null;
				}
			}
		return ret;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#read(byte[], int, int)
	 */
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int ret = super.read(b, off, len);
		if (ret > 0)
			for (int i = 0; i < copy.length; i++) {
				if (copy[i] == null)
					continue;
				try {
					copy[i].write(b, off, ret);
					copy[i].flush();
				} catch (IOException ioe) {
					copy[i] = null;
				}
			}
		return ret;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#read(byte[])
	 */
	@Override
	public int read(byte[] b) throws IOException {
		return this.read(b, 0, b.length);
	}

	/**
	 * a method to read a line from the stream up to and including the CR or
	 * CRLF.
	 * 
	 * We read character by character so that we don't read further than we
	 * should i.e. into the next line, which could be a message body, or the
	 * next message!
	 * 
	 * @param is
	 *            The InputStream to read the line from
	 * @throws IOException
	 *             if an IOException occurs while reading from the supplied
	 *             InputStream
	 * @return the line that was read, WITHOUT the CR or CRLF
	 */
	public String readLine() throws IOException {
		StringBuffer line = new StringBuffer();
		int i;
		char c = 0x00;
		i = read();
		if (i == -1)
			return null;
		while (i > -1 && i != 10 && i != 13) {
			// Convert the int to a char
			c = (char) (i & 0xFF);
			line = line.append(c);
			i = read();
		}
		if (i == 13) { // 10 is unix LF, but DOS does 13+10, so read the 10 if
			// we got 13
			if ((i = read()) != 10)
				System.out.println("Unexpected character "
						+ Integer.toHexString(i) + ". Expected 0x0d");
		}
		return line.toString();
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.io.FilterInputStream#close()
	 */
	@Override
	public void close() throws IOException {
		super.close();
		for (int i = 0; i < copy.length; i++) {
			if (copy[i] != null)
				copy[i].close();
		}
	}

}
