package org.owasp.proxy.httpclient;

import java.lang.ref.WeakReference;

import org.owasp.proxy.util.AsciiString;
import org.owasp.proxy.util.MessageUtils;

public interface MutableBufferedResponse extends MutableResponseHeader,
		MutableBufferedMessage, BufferedResponse {

	/**
	 * Allows the caller to avoid dealing with Transfer-Encoding and
	 * Content-Encoding details.
	 * 
	 * The content provided will have Chunking and Gzip, etc encodings applied
	 * as specified by the message header, before being set as the message
	 * content.
	 * 
	 * @param content
	 * @throws MessageFormatException
	 */
	public void setDecodedContent(byte[] content) throws MessageFormatException;

	public static class Impl extends MutableResponseHeader.Impl implements
			MutableBufferedResponse {

		private byte[] content;

		private WeakReference<byte[]> decoded = null;

		public void setContent(byte[] content) {
			this.content = content;
			decoded = null;
		}

		public byte[] getContent() {
			return content;
		}

		/**
		 * this method automatically performs any necessary Chunked or Gzip
		 * decoding on the message content required to obtain the actual entity
		 * content.
		 * 
		 * The decoded content is cached using a weak reference to reduce the
		 * need to perform repeated decoding operations
		 */
		public byte[] getDecodedContent() throws MessageFormatException {
			if (content == null)
				return null;
			if (decoded == null || decoded.get() == null) {
				decoded = new WeakReference<byte[]>(MessageUtils.decode(this));
			}
			return decoded.get();
		}

		/**
		 * This method automatically applies any chunked or gzip encoding
		 * specified in the message headers before setting the message content.
		 * 
		 * The decoded content is cached using a WeakReference to reduce the
		 * need to perform repeated decoding operations.
		 */
		public void setDecodedContent(byte[] content)
				throws MessageFormatException {
			if (content == null) {
				this.decoded = null;
				this.content = null;
			} else {
				decoded = new WeakReference<byte[]>(content);
				this.content = MessageUtils.encode(this, content);
			}
		}

		@Override
		public String toString() {
			return super.toString()
					+ (content != null ? AsciiString.create(content) : "");
		}

	}

}