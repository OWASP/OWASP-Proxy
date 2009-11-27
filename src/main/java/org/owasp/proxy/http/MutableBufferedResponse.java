package org.owasp.proxy.http;

import java.lang.ref.WeakReference;

import org.owasp.proxy.util.AsciiString;

public interface MutableBufferedResponse extends MutableResponseHeader,
		MutableBufferedMessage, BufferedResponse {

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