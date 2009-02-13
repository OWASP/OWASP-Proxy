package org.owasp.httpclient;

import java.util.LinkedList;
import java.util.List;

/**
 * The MessageHeader class is the base class for the HTTP Message, Request and
 * Response classes.
 * 
 * It attempts to be binary clean when the &quot;lowest-level&quot; methods are
 * used, namely:
 * <ul>
 * <li>{@link #getHeader()}</li>
 * <li>{@link #setHeader(byte[])}</li>
 * </ul>
 * 
 * Getting more convenient, there are methods that parse the &quot;header&quot;
 * into lines and allow manipulation thereof:
 * <ul>
 * <li>{@link #getHeaders()}</li>
 * <li>{@link #setHeaders(NamedValue[])}</li>
 * <li>{@link #addHeader(String, String)}</li>
 * <li>{@link #deleteHeader(String)}</li>
 * </ul>
 * 
 */
public class MessageHeader {

	private static final byte[] CRLF = { '\r', '\n' };

	protected byte[] header = null;

	public MessageHeader() {
	}

	public void setHeader(byte[] header) {
		this.header = header;
		if (header != null)
			if (header.length < 4) {
				throw new IllegalStateException(
						"The header does not end with CRLFCRLF");
			} else {
				for (int i = 0; i < 4; i++) {
					if (header[header.length - 4 + i] != CRLF[i % 2])
						throw new IllegalStateException(
								"The header does not end with CRLFCRLF");
				}
			}
	}

	public byte[] getHeader() {
		return header;
	}

	/**
	 * @param bytes
	 * @param separator
	 * @param start
	 * @return
	 */
	protected int findSeparator(byte[] bytes, byte[] separator, int start) {
		if (bytes == null)
			throw new NullPointerException("array is null");
		if (bytes.length - start < separator.length)
			return -1;
		int sep = start;
		int i = 0;
		while (sep <= bytes.length - separator.length && i < separator.length) {
			if (bytes[sep + i] == separator[i]) {
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
	 * @param separator
	 * @return
	 * @throws MessageFormatException
	 */
	protected String[] getHeaderLines(byte[] separator)
			throws MessageFormatException {
		if (header == null)
			return null;
		List<String> lines = new LinkedList<String>();
		int sep, start = 0;
		while ((sep = findSeparator(header, separator, start)) > -1
				&& sep > start) {
			lines.add(AsciiString.create(header, start, sep - start));
			start = sep + separator.length;
		}
		return lines.toArray(new String[lines.size()]);
	}

	/**
	 * @param lines
	 * @param separator
	 * @throws MessageFormatException
	 */
	protected void setHeaderLines(String[] lines, byte[] separator)
			throws MessageFormatException {
		String sep = AsciiString.create(separator);
		StringBuilder buff = new StringBuilder();
		for (int i = 0; i < lines.length; i++) {
			buff.append(lines[i]).append(sep);
		}
		buff.append(sep);
		setHeader(AsciiString.getBytes(buff.toString()));
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
}
