package org.owasp.httpclient;

import java.io.InputStream;

public interface StreamingRequest extends MutableRequestHeader, StreamingMessage {

	public class Impl extends MutableRequestHeader.Impl implements StreamingRequest {

		public Impl() {
		}

		public Impl(MutableRequestHeader header) {
			setTarget(header.getTarget());
			setSsl(header.isSsl());
			setHeader(header.getHeader());
		}

		private InputStream content;

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.StreamingResponse#getContent()
		 */
		public InputStream getContent() {
			return content;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.owasp.httpclient.StreamingResponse#setContent(java.io.InputStream
		 * )
		 */
		public void setContent(InputStream content) {
			this.content = content;
		}

	}

}
