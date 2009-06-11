package org.owasp.httpclient;

import java.net.InetSocketAddress;

public interface MutableRequestHeader extends RequestHeader, MutableMessageHeader {

	void setTarget(InetSocketAddress target);

	void setSsl(boolean ssl);

	void setMethod(String method) throws MessageFormatException;

	void setResource(String resource) throws MessageFormatException;

	void setVersion(String version) throws MessageFormatException;

	public static class Impl extends MutableMessageHeader.Impl implements
			MutableRequestHeader {

		private InetSocketAddress target;

		private boolean ssl;

		public InetSocketAddress getTarget() {
			return target;
		}

		public void setTarget(InetSocketAddress target) {
			this.target = target;
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
						"HTTP Version may not contain whitespace", header);
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
						"HTTP version may not contain whitespace", header);
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
			return (ssl ? "SSL " : "") + target + "\n" + super.toString();
		}
	}
}
