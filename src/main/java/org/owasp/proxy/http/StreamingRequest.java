package org.owasp.proxy.http;

import java.io.IOException;
import java.io.InputStream;


public interface StreamingRequest extends MutableRequestHeader,
		StreamingMessage {

	public class Impl extends MutableRequestHeader.Impl implements
			StreamingRequest {

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

		public InputStream getDecodedContent() throws MessageFormatException {
			try {
				return MessageUtils.decode(this, content);
			} catch (IOException ioe) {
				MessageFormatException mfe = new MessageFormatException(
						"Error decoding content");
				mfe.initCause(ioe);
				throw mfe;
			}
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

		public void setDecodedContent(InputStream content)
				throws MessageFormatException {
			this.content = MessageUtils.encode(this, content);
		}

	}

}
