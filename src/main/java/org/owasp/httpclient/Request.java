package org.owasp.httpclient;

public interface Request extends RequestHeader, Message {

	void setHost(String host);

	String getHost();

	void setPort(int port);

	int getPort();

	void setSsl(boolean ssl);

	boolean isSsl();

	public static class Impl extends RequestHeader.Impl implements Request {

		private String host;

		private int port;

		private boolean ssl;

		private byte[] content;

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

		public void setContent(byte[] content) {
			this.content = content;
		}

		public byte[] getContent() {
			return content;
		}

	}

}
