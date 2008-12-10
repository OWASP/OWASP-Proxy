package org.owasp.webscarab.model;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Response extends Message {

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
	
	public static boolean flushContent(String method, Response response, InputStream in, OutputStream out) throws MessageFormatException, IOException {
		String status = response.getStatus();
		if ("HEAD".equalsIgnoreCase(method) || "204".equals(status)
				|| "304".equals(status)) 
			return false;
		return Message.flushContent(response, in, out);
	}
	
}
