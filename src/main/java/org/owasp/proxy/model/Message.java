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
import java.io.UnsupportedEncodingException;
import java.util.LinkedList;
import java.util.List;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.owasp.proxy.io.ChunkedInputStream;
import org.owasp.proxy.io.ChunkedOutputStream;
import org.owasp.proxy.io.FixedLengthInputStream;

/**
 * The Message class is the base class for the HTTP Request and Response
 * classes.
 * 
 * It attempts to be binary clean when the &quot;lowest-level&quot; methods are
 * used, namely:
 * <ul>
 * <li>getMessage()</li>
 * <li>setMessage(byte[])</li>
 * </ul>
 * 
 * You can use these methods to examine the raw bytes that were set, e.g. by
 * reading from a network connection. OWASP Proxy will also use these methods
 * when writing the At the next level, there are two sets of convenience
 * methods, which split the message into &quot;header&quot; and
 * &quot;content&quot;, at the first CRLFCRLF sequence found.
 * <ul>
 * <li>getHeader()</li>
 * <li>setHeader(byte[])</li>
 * <li>getContent()</li>
 * <li>setContent(byte[])</li>
 * </ul>
 * 
 * Getting more convenient, there are methods that parse the &quot;header&quot;
 * into lines and allow manipulation thereof:
 * <ul>
 * <li>getHeaders()</li>
 * <li>setHeaders(NamedValue[])</li>
 * <li>addHeader(String, String)</li>
 * <li>addHeader(NamedValue)</li>
 * <li>deleteHeader(String)</li>
 * </ul>
 * 
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
public class Message {

	private static int sequence = 1;

	private int id;

	private static byte[] CRLF = new byte[] { 0x0D, 0x0A };

	private static byte[] CRLFCRLF = new byte[] { 0x0D, 0x0A, 0x0D, 0x0A };

	private byte[] message = null;

	private byte[] separator = CRLFCRLF;

	private volatile String[] headerLines = null;

	protected Message() {
		synchronized (Message.class) {
			id = sequence++;
		}
	}

	protected Message(int id) {
		synchronized (Message.class) {
			if (sequence <= id)
				sequence = id + 1;
			this.id = id;
		}
	}

	protected void clearCaches() {
		headerLines = null;
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
		return message;
	}

	/**
	 * @param message
	 */
	public void setMessage(byte[] message) {
		setMessage(message, CRLFCRLF);
	}

	public void setMessage(byte[] message, byte[] separator) {
		this.message = message;
		this.separator = separator;
		clearCaches();
	}

	/**
	 * @param header
	 * @param separator
	 * @param content
	 */
	public void setMessage(byte[] header, byte[] separator, byte[] content) {
		byte[] message = new byte[header.length + separator.length
				+ (content == null ? 0 : content.length)];
		System.arraycopy(header, 0, message, 0, header.length);
		System
				.arraycopy(separator, 0, message, header.length,
						separator.length);
		if (content != null)
			System.arraycopy(content, 0, message, header.length
					+ separator.length, content.length);
		setMessage(message, separator);
	}

	/**
	 * @param bytes
	 * @param separator
	 * @param start
	 * @return
	 */
	private int findSeparator(byte[] bytes, byte[] separator, int start) {
		if (bytes == null)
			throw new NullPointerException("array is null");
		if (bytes.length - start < separator.length)
			return -1;
		int sep = start;
		int i = 0;
		while (sep <= bytes.length - separator.length && i < separator.length) {
			if (bytes[sep + i] == CRLFCRLF[i]) {
				i++;
			} else {
				i = 0;
				sep++;
			}
		}
		if (i == separator.length)
			return sep;
		return -1;
	}

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	public byte[] getHeader() throws MessageFormatException {
		if (message == null)
			return null;
		int sep = findSeparator(message, separator, 0);
		if (sep == -1)
			throw new MessageFormatException("No separator found");
		byte[] header = new byte[sep];
		System.arraycopy(message, 0, header, 0, sep);
		return header;
	}

	/**
	 * @param header
	 * @throws MessageFormatException
	 */
	public void setHeader(byte[] header) throws MessageFormatException {
		setMessage(header, separator, getContent());
	}

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	public byte[] getContent() throws MessageFormatException {
		if (message == null)
			return null;
		int sep = findSeparator(message, separator, 0);
		if (sep == -1)
			throw new MessageFormatException("No separator found");
		if (sep < message.length - separator.length) {
			byte[] content = new byte[message.length - sep - separator.length];
			System.arraycopy(message, sep + separator.length, content, 0,
					content.length);
			return content;
		}
		return null;
	}

	/**
	 * @param content
	 * @throws MessageFormatException
	 */
	public void setContent(byte[] content) throws MessageFormatException {
		setMessage(getHeader(), separator, content);
	}

	/**
	 * @param separator
	 * @return
	 * @throws MessageFormatException
	 */
	protected String[] getHeaderLines(byte[] separator)
			throws MessageFormatException {
		if (headerLines != null)
			return headerLines;
		byte[] header = getHeader();
		if (header == null)
			return null;
		List<String> lines = new LinkedList<String>();
		int sep, start = 0;
		try {
			while ((sep = findSeparator(header, separator, start)) > -1) {
				lines.add(new String(header, start, sep - start, "ASCII"));
				start = sep + separator.length;
			}
			if (start < header.length)
				lines.add(new String(header, start, header.length - start,
						"ASCII"));
		} catch (UnsupportedEncodingException e) {
			// this should never happen
			e.printStackTrace();
		}
		headerLines = lines.toArray(new String[lines.size()]);
		return headerLines;
	}

	/**
	 * @param lines
	 * @param separator
	 * @throws MessageFormatException
	 */
	protected void setHeaderLines(String[] lines, byte[] separator)
			throws MessageFormatException {
		try {
			String sep = new String(separator, "ASCII");
			StringBuilder buff = new StringBuilder();
			for (int i = 0; i < lines.length; i++) {
				buff.append(lines[i]);
				if (i < lines.length - 1)
					buff.append(sep);
			}
			setHeader(buff.toString().getBytes("ASCII"));
		} catch (UnsupportedEncodingException e) {
			// this should never happen
			e.printStackTrace();
		}
	}

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	public String getStartLine() throws MessageFormatException {
		String[] lines = getHeaderLines(CRLF);
		if (lines == null || lines.length == 0)
			return null;
		return lines[0];
	}

	/**
	 * @param line
	 * @throws MessageFormatException
	 */
	public void setStartLine(String line) throws MessageFormatException {
		String[] lines = getHeaderLines(CRLF);
		if (lines == null || lines.length == 0)
			lines = new String[1];
		lines[0] = line;
		setHeaderLines(lines, CRLF);
	}

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	public NamedValue[] getHeaders() throws MessageFormatException {
		String[] lines = getHeaderLines(CRLF);
		if (lines == null || lines.length <= 1)
			return null;
		NamedValue[] headers = new NamedValue[lines.length - 1];
		for (int i = 0; i < headers.length; i++)
			headers[i] = NamedValue.parse(lines[i + 1], " *: *");
		return headers;
	}

	/**
	 * @param headers
	 * @throws MessageFormatException
	 */
	public void setHeaders(NamedValue[] headers) throws MessageFormatException {
		String[] lines = new String[(headers == null ? 0 : headers.length) + 1];
		lines[0] = getStartLine();
		if (lines[0] == null)
			throw new MessageFormatException(
					"No start line found, can't set headers without one!");
		if (headers != null)
			for (int i = 0; i < headers.length; i++) {
				lines[i + 1] = headers[i].toString();
			}
		setHeaderLines(lines, CRLF);
	}

	/**
	 * @param name
	 * @return
	 * @throws MessageFormatException
	 */
	public String getHeader(String name) throws MessageFormatException {
		NamedValue[] headers = getHeaders();
		if (headers == null || headers.length == 0)
			return null;
		for (int i = 0; i < headers.length; i++)
			if (name.equalsIgnoreCase(headers[i].getName()))
				return headers[i].getValue();
		return null;
	}

	/**
	 * @param name
	 * @param value
	 * @throws MessageFormatException
	 */
	public void setHeader(String name, String value)
			throws MessageFormatException {
		NamedValue[] headers = getHeaders();
		if (headers != null && headers.length != 0) {
			for (int i = 0; i < headers.length; i++)
				if (name.equalsIgnoreCase(headers[i].getName())) {
					headers[i] = new NamedValue(name,
							headers[i].getSeparator(), value);
					setHeaders(headers);
					return;
				}
		}
		addHeader(headers, name, value);
	}

	/**
	 * @param name
	 * @param value
	 * @throws MessageFormatException
	 */
	public void addHeader(String name, String value)
			throws MessageFormatException {
		addHeader(getHeaders(), name, value);
	}

	/**
	 * @param headers
	 * @param name
	 * @param value
	 * @throws MessageFormatException
	 */
	private void addHeader(NamedValue[] headers, String name, String value)
			throws MessageFormatException {
		if (headers == null) {
			headers = new NamedValue[1];
		} else {
			NamedValue[] nh = new NamedValue[headers.length + 1];
			System.arraycopy(headers, 0, nh, 0, headers.length);
			headers = nh;
		}
		headers[headers.length - 1] = new NamedValue(name, ": ", value);
		setHeaders(headers);
	}

	/**
	 * @param name
	 * @return
	 * @throws MessageFormatException
	 */
	public String deleteHeader(String name) throws MessageFormatException {
		NamedValue[] headers = getHeaders();
		if (headers == null || headers.length == 0)
			return null;
		for (int i = 0; i < headers.length; i++)
			if (name.equalsIgnoreCase(headers[i].getName())) {
				String ret = headers[i].getValue();
				NamedValue[] nh = new NamedValue[headers.length - 1];
				if (i > 0)
					System.arraycopy(headers, 0, nh, 0, i);
				if (i < headers.length - 1)
					System.arraycopy(headers, i + 1, nh, i, headers.length - i
							- 1);
				setHeaders(nh);
				return ret;
			}
		return null;
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

	/**
	 * @return
	 * @throws MessageFormatException
	 */
	protected String[] getStartParts() throws MessageFormatException {
		String startLine = getStartLine();
		if (startLine == null)
			return new String[0];
		return startLine.split("[ \t]+", 3);
	}

	/**
	 * @param parts
	 * @throws MessageFormatException
	 */
	protected void setStartParts(String[] parts) throws MessageFormatException {
		if (parts == null || parts.length == 0) {
			setStartLine("");
		} else {
			StringBuilder b = new StringBuilder(parts[0] == null ? ""
					: parts[0]);
			for (int i = 1; i < parts.length; i++)
				b.append(" ").append(parts[i] == null ? "" : parts[i]);
			setStartLine(b.toString());
		}
	}

	@Override
	public String toString() {
		return new String(message);
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
