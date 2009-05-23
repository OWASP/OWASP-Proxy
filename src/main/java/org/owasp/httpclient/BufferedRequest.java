package org.owasp.httpclient;

import org.owasp.httpclient.util.AsciiString;

public interface BufferedRequest extends RequestHeader, BufferedMessage,
		ReadOnlyBufferedRequest {

	public static class Impl extends RequestHeader.Impl implements
			BufferedRequest {

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
