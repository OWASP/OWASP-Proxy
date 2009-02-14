package org.owasp.httpclient.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.owasp.httpclient.Message;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MessageHeader;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.io.ChunkedInputStream;
import org.owasp.httpclient.io.ChunkedOutputStream;
import org.owasp.httpclient.io.FixedLengthInputStream;

public class MessageUtils {

	/**
	 * @param content
	 * @param codings
	 * @return
	 * @throws MessageFormatException
	 */
	public static InputStream decode(MessageHeader header, InputStream content)
			throws MessageFormatException {
		String codings = header.getHeader("Transfer-Coding");
		if (codings == null || codings.trim().equals(""))
			return content;
		try {
			String[] algos = codings.split("[ \t]*,[ \t]*");
			if (algos.length == 1 && "identity".equalsIgnoreCase(algos[0]))
				return content;
			for (int i = 0; i < algos.length; i++) {
				if ("chunked".equalsIgnoreCase(algos[i])) {
					content = new ChunkedInputStream(content);
				} else if ("gzip".equalsIgnoreCase(algos[i])) {
					content = new GZIPInputStream(content);
				} else if ("identity".equalsIgnoreCase(algos[i])) {
					// nothing to do
				} else
					throw new MessageFormatException("Unsupported coding : "
							+ algos[i]);
			}
			return content;
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
	public static OutputStream encode(MessageHeader header, OutputStream content)
			throws MessageFormatException {
		String codings = header.getHeader("Transfer-Coding");
		if (codings == null || codings.trim().equals(""))
			return content;
		try {
			String[] algos = codings.split("[ \t]*,[ \t]*");
			if (algos.length == 1 && "identity".equalsIgnoreCase(algos[0]))
				return content;
			for (int i = 0; i < algos.length; i++) {
				if ("chunked".equalsIgnoreCase(algos[i])) {
					content = new ChunkedOutputStream(content);
				} else if ("gzip".equalsIgnoreCase(algos[i])) {
					content = new GZIPOutputStream(content);
				} else if ("identity".equalsIgnoreCase(algos[i])) {
					// nothing to do
				} else
					throw new MessageFormatException("Unsupported coding : "
							+ algos[i]);
			}
			return content;
		} catch (IOException ioe) {
			throw new MessageFormatException("Error encoding content", ioe);
		}
	}

	public static boolean flushContent(MessageHeader header, InputStream in)
			throws MessageFormatException, IOException {
		return flushContent(header, in, null);
	}

	public static boolean flushContent(MessageHeader header, InputStream in,
			OutputStream out) throws MessageFormatException, IOException {
		boolean read = false;
		String te = header.getHeader("Transfer-Encoding");
		if ("chunked".equalsIgnoreCase(te)) {
			in = new ChunkedInputStream(in);
		} else if (te != null) {
			throw new IOException("Unknown Transfer-Encoding '" + te + "'");
		} else {
			String cl = header.getHeader("Content-Length");
			if (cl != null) {
				try {
					int l = Integer.parseInt(cl.trim());
					if (l == 0)
						return read;
					in = new FixedLengthInputStream(in, l);
				} catch (NumberFormatException nfe) {
					throw new MessageFormatException(
							"Invalid Content-Length header: " + cl, nfe);
				}
			}
		}
		byte[] buff = new byte[2048];
		int got;
		while ((got = in.read(buff)) > 0) {
			read = true;
			if (out != null)
				out.write(buff, 0, got);
		}

		return read;
	}

	/**
	 * Get the exact representation of the message
	 * 
	 * @return the internal byte[] representing the contents of this message.
	 */
	public static byte[] getMessage(Message message) {
		byte[] header = message.getHeader();
		byte[] content = message.getContent();
		if (content != null && content.length > 0) {
			byte[] bytes = new byte[header.length + content.length];
			System.arraycopy(header, 0, bytes, 0, header.length);
			System.arraycopy(content, 0, bytes, header.length, content.length);
			return bytes;
		}
		return header;
	}

	public static boolean expectContent(RequestHeader request)
			throws MessageFormatException {
		String method = request.getMethod();
		return "POST".equals(method) || "PUT".equals(method);
	}

	public static boolean expectContent(RequestHeader request,
			ResponseHeader response) throws MessageFormatException {
		String method = request.getMethod();
		String status = response.getStatus();
		return !("HEAD".equals(method) || "204".equals(status) || "304"
				.equals(status));
	}

}
