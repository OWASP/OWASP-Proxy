package org.owasp.httpclient.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.owasp.httpclient.BufferedMessage;
import org.owasp.httpclient.BufferedRequest;
import org.owasp.httpclient.BufferedResponse;
import org.owasp.httpclient.MessageFormatException;
import org.owasp.httpclient.MessageHeader;
import org.owasp.httpclient.MutableBufferedMessage;
import org.owasp.httpclient.MutableBufferedRequest;
import org.owasp.httpclient.MutableBufferedResponse;
import org.owasp.httpclient.MutableMessageHeader;
import org.owasp.httpclient.RequestHeader;
import org.owasp.httpclient.ResponseHeader;
import org.owasp.httpclient.StreamingMessage;
import org.owasp.httpclient.StreamingRequest;
import org.owasp.httpclient.StreamingResponse;
import org.owasp.httpclient.io.ChunkedInputStream;
import org.owasp.httpclient.io.ChunkingInputStream;
import org.owasp.httpclient.io.CopyInputStream;
import org.owasp.httpclient.io.EofNotifyingInputStream;
import org.owasp.httpclient.io.FixedLengthInputStream;
import org.owasp.httpclient.io.GunzipInputStream;
import org.owasp.httpclient.io.GzipInputStream;
import org.owasp.httpclient.io.SizeLimitExceededException;
import org.owasp.httpclient.io.SizeLimitedByteArrayOutputStream;

public class MessageUtils {

	/**
	 * @param bytes
	 * @param separator
	 * @param start
	 * @return
	 */
	public static int findSeparator(byte[] bytes, byte[] separator, int start) {
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
	 * @param content
	 * @param codings
	 * @return
	 * @throws MessageFormatException
	 */
	public static InputStream decode(StreamingMessage message)
			throws IOException, MessageFormatException {
		return decode(message, message.getContent());
	}

	public static byte[] decode(BufferedMessage message)
			throws MessageFormatException {
		return decode(message, message.getContent());
	}

	public static byte[] decode(MessageHeader message, byte[] content)
			throws MessageFormatException {
		try {
			InputStream is = new ByteArrayInputStream(content);
			is = decode(message, is);
			ByteArrayOutputStream copy = new ByteArrayOutputStream();
			byte[] buff = new byte[4096];
			int got;
			while ((got = is.read(buff)) > 0)
				copy.write(buff, 0, got);
			return copy.toByteArray();
		} catch (IOException ioe) {
			throw new MessageFormatException("Malformed encoded content: "
					+ ioe.getMessage(), ioe);
		}
	}

	public static InputStream decode(MessageHeader message, InputStream content)
			throws IOException, MessageFormatException {
		if (content == null)
			return content;
		String codings = message.getHeader("Transfer-Encoding");
		content = decode(codings, content);
		codings = message.getHeader("Content-Encoding");
		content = decode(codings, content);
		return content;
	}

	public static InputStream decode(String codings, InputStream content)
			throws IOException, MessageFormatException {
		if (codings == null || codings.trim().equals(""))
			return content;
		String[] algos = codings.split("[ \t]*,[ \t]*");
		if (algos.length == 1 && "identity".equalsIgnoreCase(algos[0]))
			return content;
		for (int i = 0; i < algos.length; i++) {
			if ("chunked".equalsIgnoreCase(algos[i])) {
				content = new ChunkedInputStream(content);
			} else if ("gzip".equalsIgnoreCase(algos[i])) {
				content = new GunzipInputStream(content);
			} else if ("identity".equalsIgnoreCase(algos[i])) {
				// nothing to do
			} else
				throw new MessageFormatException("Unsupported coding : "
						+ algos[i]);
		}
		return content;
	}

	/**
	 * @param content
	 * @param codings
	 * @return
	 * @throws MessageFormatException
	 */
	public static InputStream encode(StreamingMessage message)
			throws MessageFormatException {
		return encode(message, message.getContent());
	}

	public static byte[] encode(BufferedMessage message) throws IOException,
			MessageFormatException {
		InputStream content = new ByteArrayInputStream(message.getContent());
		content = encode(message, content);
		ByteArrayOutputStream copy = new ByteArrayOutputStream();
		byte[] buff = new byte[4096];
		int got;
		while ((got = content.read(buff)) > 0)
			copy.write(buff, 0, got);
		return copy.toByteArray();
	}

	/**
	 * @param content
	 * @param codings
	 * @return
	 * @throws MessageFormatException
	 */
	public static InputStream encode(MessageHeader header, InputStream content)
			throws MessageFormatException {
		String codings = header.getHeader("Content-Encoding");
		content = encode(codings, content);
		codings = header.getHeader("Transfer-Encoding");
		content = encode(codings, content);
		return content;
	}

	public static InputStream encode(String codings, InputStream content)
			throws MessageFormatException {
		if (codings == null || codings.trim().equals(""))
			return content;
		String[] algos = codings.split("[ \t]*,[ \t]*");
		if (algos.length == 1 && "identity".equalsIgnoreCase(algos[0]))
			return content;
		for (int i = 0; i < algos.length; i++) {
			if ("chunked".equalsIgnoreCase(algos[i])) {
				content = new ChunkingInputStream(content);
			} else if ("gzip".equalsIgnoreCase(algos[i])) {
				content = new GzipInputStream(content);
			} else if ("identity".equalsIgnoreCase(algos[i])) {
				// nothing to do
			} else
				throw new MessageFormatException("Unsupported coding : "
						+ algos[i]);
		}
		return content;
	}

	public static boolean flushContent(MutableMessageHeader header,
			InputStream in) throws MessageFormatException, IOException {
		return flushContent(header, in, null);
	}

	public static boolean flushContent(MutableMessageHeader header,
			InputStream in, OutputStream out) throws MessageFormatException,
			IOException {
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
	public static byte[] getMessage(MutableBufferedMessage message) {
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

	public static void buffer(StreamingRequest request,
			MutableBufferedRequest buff, int max) throws IOException,
			SizeLimitExceededException {
		buff.setTarget(request.getTarget());
		buff.setSsl(request.isSsl());
		buffer((StreamingMessage) request, buff, max);
	}

	public static void buffer(StreamingResponse response,
			MutableBufferedResponse buff, int max) throws IOException,
			SizeLimitExceededException {
		buffer((StreamingMessage) response, buff, max);
	}

	private static void buffer(StreamingMessage message,
			MutableBufferedMessage buffered, int max) throws IOException,
			SizeLimitExceededException {
		buffered.setHeader(message.getHeader());
		InputStream in = message.getContent();
		if (in != null) {
			ByteArrayOutputStream copy;
			copy = new SizeLimitedByteArrayOutputStream(max);
			byte[] b = new byte[1024];
			int got;
			try {
				while ((got = in.read(b)) > -1) {
					copy.write(b, 0, got);
				}
				buffered.setContent(copy.toByteArray());
			} catch (SizeLimitExceededException slee) {
				buffered.setContent(copy.toByteArray());
				throw slee;
			}
		}
	}

	public static void stream(BufferedRequest request, StreamingRequest stream) {
		stream.setTarget(request.getTarget());
		stream.setSsl(request.isSsl());
		stream((BufferedMessage) request, stream);
	}

	public static void stream(BufferedResponse response,
			StreamingResponse stream) {
		stream((BufferedMessage) response, stream);
	}

	private static void stream(BufferedMessage message, StreamingMessage stream) {
		stream.setHeader(message.getHeader());
		byte[] content = message.getContent();
		if (content != null && content.length > 0)
			stream.setContent(new ByteArrayInputStream(content));
	}

	public static void delayedCopy(StreamingRequest message,
			MutableBufferedRequest copy, int max, DelayedCopyObserver observer) {
		copy.setTarget(message.getTarget());
		copy.setSsl(message.isSsl());
		delayedCopy((StreamingMessage) message, (MutableBufferedMessage) copy,
				max, observer);
	}

	public static void delayedCopy(StreamingResponse message,
			MutableBufferedResponse copy, int max, DelayedCopyObserver observer) {
		delayedCopy((StreamingMessage) message, (MutableBufferedMessage) copy,
				max, observer);
	}

	private static void delayedCopy(StreamingMessage message,
			final MutableBufferedMessage copy, int max,
			final DelayedCopyObserver observer) {
		if (observer == null)
			throw new NullPointerException("Observer may not be null");

		copy.setHeader(message.getHeader());
		InputStream content = message.getContent();
		if (content == null) {
			observer.copyCompleted();
		} else {
			final ByteArrayOutputStream copyContent = new SizeLimitedByteArrayOutputStream(
					max) {
				public void overflow() {
					observer.contentOverflow();
				}
			};
			content = new CopyInputStream(content, copyContent);
			content = new EofNotifyingInputStream(content) {
				protected void eof() {
					copy.setContent(copyContent.toByteArray());
					observer.copyCompleted();
				}
			};
			message.setContent(content);
		}
	}

	public static abstract class DelayedCopyObserver {

		public void contentOverflow() {
		}

		public abstract void copyCompleted();

	}
}
