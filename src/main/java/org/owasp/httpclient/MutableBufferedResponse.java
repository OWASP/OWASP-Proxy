package org.owasp.httpclient;

import org.owasp.httpclient.util.AsciiString;

public interface MutableBufferedResponse extends MutableResponseHeader, MutableBufferedMessage,
		BufferedResponse {

	public static class Impl extends MutableResponseHeader.Impl implements
			MutableBufferedResponse {

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