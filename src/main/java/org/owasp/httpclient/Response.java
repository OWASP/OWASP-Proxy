package org.owasp.httpclient;

import org.owasp.httpclient.util.AsciiString;

public interface Response extends ResponseHeader, Message {

	public static class Impl extends ResponseHeader.Impl implements Response {

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