package org.owasp.httpclient;

public interface MutableResponseHeader extends ResponseHeader,
		MutableMessageHeader {

	void setVersion(String version) throws MessageFormatException;

	void setStatus(String status) throws MessageFormatException;

	void setReason(String reason) throws MessageFormatException;

	void setHeaderStartedTime(long time);

	void setHeaderCompletedTime(long time);

	void setContentStartedTime(long time);

	void setContentCompletedTime(long time);

	public static class Impl extends MutableMessageHeader.Impl implements
			MutableResponseHeader {

		private long headerStartedTime = 0, headerCompletedTime = 0,
				contentStartedTime = 0, contentCompletedTime = 0;

		public void setVersion(String version) throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 1) {
				setStartParts(new String[] { version });
			} else {
				parts[0] = version;
				setStartParts(parts);
			}
		}

		public String getVersion() throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length == 0)
				return null;
			return "".equals(parts[0]) ? null : parts[0];
		}

		public void setStatus(String status) throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 2) {
				String[] p = new String[2];
				if (parts.length == 1) {
					p[0] = parts[0];
				} else {
					p[0] = null;
				}
				parts = p;
			}
			parts[1] = status;
			setStartParts(parts);
		}

		public String getStatus() throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 2)
				return null;
			return "".equals(parts[1]) ? null : parts[1];
		}

		public void setReason(String reason) throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 3) {
				String[] p = new String[3];
				if (parts.length >= 1) {
					p[0] = parts[0];
					if (parts.length >= 2) {
						p[1] = parts[1];
					} else {
						p[1] = null;
					}
				} else {
					p[0] = null;
					p[1] = null;
				}
				parts = p;
			}
			parts[2] = reason;
			setStartParts(parts);
		}

		public String getReason() throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 3)
				return null;
			return "".equals(parts[2]) ? null : parts[2];
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.owasp.httpclient.MutableResponseHeader#setHeaderCompletedTime
		 * (long)
		 */
		public void setHeaderCompletedTime(long time) {
			headerCompletedTime = time;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see
		 * org.owasp.httpclient.MutableResponseHeader#setHeaderStartedTime(long)
		 */
		public void setHeaderStartedTime(long time) {
			headerStartedTime = time;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.ResponseHeader#getHeaderCompletedTime()
		 */
		public long getHeaderCompletedTime() {
			return headerCompletedTime;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.ResponseHeader#getHeaderStartedTime()
		 */
		public long getHeaderStartedTime() {
			return headerStartedTime;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.StreamingResponse#getContentCompletedTime()
		 */
		public long getContentCompletedTime() {
			return contentCompletedTime;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.StreamingResponse#getContentStartedTime()
		 */
		public long getContentStartedTime() {
			return contentStartedTime;
		}

		public void setContentCompletedTime(long time) {
			contentCompletedTime = time;
		}

		public void setContentStartedTime(long time) {
			contentStartedTime = time;
		}

	}
}
