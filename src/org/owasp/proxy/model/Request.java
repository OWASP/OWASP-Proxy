/*
 *  This file is part of the OWASP Proxy, a free intercepting HTTP proxy
 *  library.
 *  Copyright (C) 2008  Rogan Dawes <rogan@dawes.za.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
package org.owasp.proxy.model;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class Request extends Message {

	private String scheme = null, host = null;

	private int port = -1;
	
	/**
	 * @return the scheme
	 */
	public String getScheme() {
		return scheme;
	}

	/**
	 * @param scheme the scheme to set
	 */
	public void setScheme(String scheme) {
		this.scheme = scheme;
	}

	/**
	 * @return the host
	 */
	public String getHost() {
		return host;
	}

	/**
	 * @param host the host to set
	 */
	public void setHost(String host) {
		this.host = host;
	}

	/**
	 * @return the port
	 */
	public int getPort() {
		return port;
	}

	/**
	 * @param port the port to set
	 */
	public void setPort(int port) {
		this.port = port;
	}

	@Override
	protected String[] getStartParts() throws MessageFormatException {
		String[] parts = super.getStartParts();
		if (parts.length == 3 && parts[2] != null && parts[2].matches(" \t"))
			throw new MessageFormatException("HTTP Version may not contain whitespace");
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
			throw new MessageFormatException("HTTP version may not contain whitespace");
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
	
	/**
	 * reads the entire request body from an InputStream, taking into account
	 * Transfer-Encoding and Content-Length headers
	 * 
	 * @param request the request headers
	 * @param in the InputStream
	 * @param out an OutputStream to write the entity to
	 * @return true if any bytes were read from the stream
	 * 
	 * @throws IOException
	 * @throws MessageFormatException if the request headers could not be parsed
	 */
    public static boolean flushContent(Request request, InputStream in, OutputStream out) throws IOException, MessageFormatException {
    	String method = request.getMethod();
    	if (!"POST".equals(method) && !"PUT".equals(method))
    		return false;
    	return Message.flushContent(request, in, out);
    }

	/**
	 * reads the entire request body from an InputStream, taking into account
	 * Transfer-Encoding and Content-Length headers
	 * 
	 * @param request the request headers
	 * @param in the InputStream
	 * @return true if any bytes were read from the stream
	 * 
	 * @throws IOException
	 * @throws MessageFormatException if the request headers could not be parsed
	 */
    public static boolean flushContent(Request request, InputStream in) throws IOException, MessageFormatException {
    	return Request.flushContent(request, in, null);
    }

}
