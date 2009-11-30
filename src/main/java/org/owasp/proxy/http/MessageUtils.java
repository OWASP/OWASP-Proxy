package org.owasp.proxy.http;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import org.owasp.proxy.io.ChunkedInputStream;
import org.owasp.proxy.io.ChunkingInputStream;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.io.CountingInputStream;
import org.owasp.proxy.io.FixedLengthInputStream;
import org.owasp.proxy.io.GunzipInputStream;
import org.owasp.proxy.io.GzipInputStream;
import org.owasp.proxy.io.SizeLimitExceededException;
import org.owasp.proxy.io.SizeLimitedByteArrayOutputStream;

public class MessageUtils {

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

	public static byte[] encode(BufferedMessage message)
			throws MessageFormatException {
		return encode(message, message.getContent());
	}

	public static byte[] encode(MessageHeader header, byte[] content)
			throws MessageFormatException {
		InputStream contentStream = new ByteArrayInputStream(content);
		contentStream = encode(header, contentStream);
		ByteArrayOutputStream copy = new ByteArrayOutputStream();
		byte[] buff = new byte[4096];
		int got;
		try {
			while ((got = contentStream.read(buff)) > 0)
				copy.write(buff, 0, got);
		} catch (IOException ioe) {
			throw new MessageFormatException("Error encoding content", ioe);
		}
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
			final MutableBufferedMessage copy, final int max,
			final DelayedCopyObserver observer) {
		if (observer == null)
			throw new NullPointerException("Observer may not be null");

		copy.setHeader(message.getHeader());
		InputStream content = message.getContent();
		if (content == null) {
			observer.copyCompleted(false, 0);
		} else {
			final ByteArrayOutputStream copyContent = new SizeLimitedByteArrayOutputStream(
					max) {
				@Override
				protected void overflow() {
					// do not throw an exception
				}
			};
			content = new CopyInputStream(content, copyContent);
			content = new CountingInputStream(content) {
				protected void eof() {
					copy.setContent(copyContent.toByteArray());
					observer.copyCompleted(getCount() > max, getCount());
				}
			};
			message.setContent(content);
		}
	}

	public static abstract class DelayedCopyObserver {

		public abstract void copyCompleted(boolean overflow, int size);

	}

	public static boolean isExpectContinue(RequestHeader request)
			throws MessageFormatException {
		return "100-continue".equalsIgnoreCase(request.getHeader("Expect"));
	}

}
