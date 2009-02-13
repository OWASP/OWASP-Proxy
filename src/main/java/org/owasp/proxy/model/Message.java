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
package org.owasp.proxy.model;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.owasp.httpclient.ChunkedInputStream;
import org.owasp.httpclient.FixedLengthInputStream;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MessageHeader;
import org.owasp.proxy.io.ChunkedOutputStream;

/**
 * Finally, there are two methods that operate on the content, processing it
 * according to the Content-Encoding and Transfer-Encoding headers:
 * <ul>
 * <li>getEntity()</li>
 * <li>setEntity(byte[])</li>
 * </ul>
 * 
 * @author Rogan Dawes
 * 
 */
public class Message extends MessageHeader {

	private int id = -1;

	private static byte[] CRLFCRLF = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A };

	private byte[] content = null;

	public void setId(int id) {
		this.id = id;
	}

	public int getId() {
		return id;
	}

	/**
	 * Get the exact representation of the message
	 * 
	 * @return the internal byte[] representing the contents of this message.
	 */
	public byte[] getMessage() {
		byte[] header = getHeader();
		if (content != null && content.length > 0) {
			byte[] message = new byte[header.length + content.length];
			System.arraycopy(header, 0, message, 0, header.length);
			System
					.arraycopy(content, 0, message, header.length,
							content.length);
			return message;
		}
		return header;
	}

	/**
	 * @param message
	 */
	public void setMessage(byte[] message) {
		if (message == null || message.length == 0) {
			setHeader(null);
			setContent(null);
		} else {
			int sep = findSeparator(message, CRLFCRLF, 0);
			if (sep != -1 && sep < message.length) {
				byte[] header = new byte[sep + 4];
				System.arraycopy(message, 0, header, 0, sep + 4);
				byte[] content = new byte[message.length - (sep + 4)];
				System.arraycopy(message, sep + 4, content, 0, content.length);
				setHeader(header);
				setContent(content);
			} else {
				setHeader(message);
			}
		}
	}

	//
	// public void setMessage(byte[] message, byte[] separator) {
	// this.message = message;
	// this.separator = separator;
	// clearCaches();
	// }
	//
	// /**
	// * @param header
	// * @param separator
	// * @param content
	// */
	// public void setMessage(byte[] header, byte[] separator, byte[] content) {
	// byte[] message = new byte[header.length + separator.length
	// + (content == null ? 0 : content.length)];
	// System.arraycopy(header, 0, message, 0, header.length);
	// System
	// .arraycopy(separator, 0, message, header.length,
	// separator.length);
	// if (content != null)
	// System.arraycopy(content, 0, message, header.length
	// + separator.length, content.length);
	// setMessage(message, separator);
	// }
	//

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	public byte[] getContent() {
		return content;
	}

	/**
	 * @param content
	 * @throws MessageFormatException
	 */
	public void setContent(byte[] content) {
		this.content = content;
	}

	/**
	 * @param content
	 * @param codings
	 * @return
	 * @throws MessageFormatException
	 */
	private byte[] decode(byte[] content, String codings)
			throws MessageFormatException {
		if (codings == null || codings.trim().equals(""))
			return content;
		try {
			String[] algos = codings.split("[ \t]*,[ \t]*");
			if (algos.length == 1 && "identity".equalsIgnoreCase(algos[0]))
				return content;
			InputStream is = new ByteArrayInputStream(content);
			for (int i = 0; i < algos.length; i++) {
				if ("chunked".equalsIgnoreCase(algos[i])) {
					is = new ChunkedInputStream(is);
				} else if ("gzip".equalsIgnoreCase(algos[i])) {
					is = new GZIPInputStream(is);
				} else if ("identity".equalsIgnoreCase(algos[i])) {
					// nothing to do
				} else
					throw new MessageFormatException("Unsupported coding : "
							+ algos[i]);
			}
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			byte[] buff = new byte[4096];
			int got;
			while ((got = is.read(buff)) > 0)
				baos.write(buff, 0, got);
			return baos.toByteArray();
		} catch (IOException ioe) {
			throw new MessageFormatException("Error decoding content", ioe);
		}
	}

	/**
	 * @param content
	 * @param codings
	 * @return
	 * @throws MessageFormatException
	 */
	private byte[] encode(byte[] content, String codings)
			throws MessageFormatException {
		if (codings == null || codings.trim().equals(""))
			return content;
		try {
			String[] algos = codings.split("[ \t]*,[ \t]*");
			if (algos.length == 1 && "identity".equalsIgnoreCase(algos[0]))
				return content;
			ByteArrayOutputStream baos = new ByteArrayOutputStream();
			OutputStream os = baos;
			for (int i = 0; i < algos.length; i++) {
				if ("chunked".equalsIgnoreCase(algos[i])) {
					os = new ChunkedOutputStream(os);
				} else if ("gzip".equalsIgnoreCase(algos[i])) {
					os = new GZIPOutputStream(os);
				} else if ("identity".equalsIgnoreCase(algos[i])) {
					// nothing to do
				} else
					throw new MessageFormatException("Unsupported coding : "
							+ algos[i]);
			}
			os.write(content);
			os.flush();
			return baos.toByteArray();
		} catch (IOException ioe) {
			throw new MessageFormatException("Error encoding content", ioe);
		}
	}

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	public byte[] getEntity() throws MessageFormatException {
		byte[] transportDecoded = decode(getContent(),
				getHeader("Transport-Encoding"));
		byte[] contentDecoded = decode(transportDecoded,
				getHeader("Content-Encoding"));
		return contentDecoded;
	}

	/**
	 * @param decoded
	 * @throws MessageFormatException
	 */
	public void setEntity(byte[] decoded) throws MessageFormatException {
		byte[] contentEncoded = encode(decoded, getHeader("Content-Encoding"));
		byte[] transportEncoded = encode(contentEncoded,
				getHeader("Transport-Encoding"));
		setContent(transportEncoded);
	}

	@Override
	public String toString() {
		return new String(getHeader()) + new String(getContent());
	}

	public static boolean flushContent(Message message, InputStream in,
			OutputStream out) throws MessageFormatException, IOException {
		String te = message.getHeader("Transfer-Encoding");
		if ("chunked".equalsIgnoreCase(te)) {
			in = new ChunkedInputStream(in);
		} else if (te != null) {
			throw new IOException("Unknown Transfer-Encoding '" + te + "'");
		} else {
			String cl = message.getHeader("Content-Length");
			if (cl != null) {
				try {
					int l = Integer.parseInt(cl.trim());
					if (l == 0)
						return false;
					in = new FixedLengthInputStream(in, l);
				} catch (NumberFormatException nfe) {
					throw new MessageFormatException(
							"Invalid Content-Length header: " + cl, nfe);
				}
			}
		}
		byte[] buff = new byte[2048];
		int got;
		while ((got = in.read(buff)) > 0)
			if (out != null)
				out.write(buff, 0, got);

		return true;
	}
}
