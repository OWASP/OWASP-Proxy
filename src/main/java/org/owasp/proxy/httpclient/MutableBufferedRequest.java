package org.owasp.proxy.httpclient;

import org.owasp.proxy.util.AsciiString;

public interface MutableBufferedRequest extends MutableRequestHeader, MutableBufferedMessage,
		BufferedRequest {

	public static class Impl extends MutableRequestHeader.Impl implements
			MutableBufferedRequest {

		private byte[] content;

		public void setContent(byte[] content) {
			this.content = content;
		}

		public byte[] getContent() {
			return content;
		}

		@Override
		public String toString() {
			return super.toString()
					+ (content != null ? AsciiString.create(content) : "");
		}
	}

}
