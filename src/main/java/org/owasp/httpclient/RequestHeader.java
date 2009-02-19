package org.owasp.httpclient;

public interface RequestHeader extends MessageHeader {

	void setHost(String host);

	String getHost();

	void setPort(int port);

	int getPort();

	void setSsl(boolean ssl);

	boolean isSsl();

	void setMethod(String method) throws MessageFormatException;

	String getMethod() throws MessageFormatException;

	void setResource(String resource) throws MessageFormatException;

	String getResource() throws MessageFormatException;

	void setVersion(String version) throws MessageFormatException;

	String getVersion() throws MessageFormatException;

	public static class Impl extends MessageHeader.Impl implements
			RequestHeader {

		private String host;

		private int port;

		private boolean ssl;

		public String getHost() {
			return host;
		}

		public void setHost(String host) {
			this.host = host;
		}

		public int getPort() {
			return port;
		}

		public void setPort(int port) {
			this.port = port;
		}

		public boolean isSsl() {
			return ssl;
		}

		public void setSsl(boolean ssl) {
			this.ssl = ssl;
		}

		@Override
		protected String[] getStartParts() throws MessageFormatException {
			String[] parts = super.getStartParts();
			if (parts.length == 3 && parts[2] != null
					&& parts[2].matches(" \t"))
				throw new MessageFormatException(
						"HTTP Version may not contain whitespace");
			return parts;
		}

		public void setMethod(String method) throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 1) {
				setStartParts(new String[] { method });
			} else {
				parts[0] = method;
				setStartParts(parts);
			}
		}

		public String getMethod() throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length == 0)
				return null;
			return "".equals(parts[0]) ? null : parts[0];
		}

		public void setResource(String resource) throws MessageFormatException {
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
			parts[1] = resource;
			setStartParts(parts);
		}

		public String getResource() throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 2)
				return null;
			return "".equals(parts[1]) ? null : parts[1];
		}

		public void setVersion(String version) throws MessageFormatException {
			if (version != null && version.matches(" \t"))
				throw new MessageFormatException(
						"HTTP version may not contain whitespace");
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
			parts[2] = version;
			setStartParts(parts);
		}

		public String getVersion() throws MessageFormatException {
			String[] parts = getStartParts();
			if (parts.length < 3)
				return null;
			return "".equals(parts[2]) ? null : parts[2];
		}

		@Override
		public String toString() {
			return ssl ? "SSL " : "" + host + ":" + port + "\n"
					+ super.toString();
		}
	}
}
