package org.owasp.proxy.httpclient;

public interface MutableResponseHeader extends ResponseHeader,
		MutableMessageHeader {

	void setVersion(String version) throws MessageFormatException;

	void setStatus(String status) throws MessageFormatException;

	void setReason(String reason) throws MessageFormatException;

	void setHeaderTime(long time);

	void setContentTime(long time);

	public static class Impl extends MutableMessageHeader.Impl implements
			MutableResponseHeader {

		private long headerTime = 0, contentTime = 0;

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
				p[0] = parts.length >= 1 ? parts[0] : "HTTP/1.0";
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
				p[0] = parts.length >= 1 ? parts[0] : "HTTP/1.0";
				p[1] = parts.length >= 2 ? parts[1] : "200";
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
		 * org.owasp.httpclient.MutableResponseHeader#setHeaderStartedTime(long)
		 */
		public void setHeaderTime(long time) {
			headerTime = time;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.ResponseHeader#getHeaderCompletedTime()
		 */
		public long getHeaderTime() {
			return headerTime;
		}

		public void setContentTime(long time) {
			contentTime = time;
		}

		/*
		 * (non-Javadoc)
		 * 
		 * @see org.owasp.httpclient.StreamingResponse#getContentCompletedTime()
		 */
		public long getContentTime() {
			return contentTime;
		}

	}
}
