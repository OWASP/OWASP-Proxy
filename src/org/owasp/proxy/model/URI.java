package org.owasp.proxy.model;

import java.net.URISyntaxException;

public class URI {

	private String input, scheme, host, path, query, fragment;

	private int port = -1;

	public URI(String url) throws URISyntaxException {
		input = url;
		parseHierarchical();
	}

	private void parseHierarchical() throws URISyntaxException {
		int length = input.length();
		int start = 0, end;
		end = scan(start, ":");
		if (end == length)
			throw new URISyntaxException(input,
					"No ':' found extracting the scheme");
		scheme = input.substring(start, end);
		
		if (end > length - 3 || !"://".equals(input.substring(end, end + 3)))
			throw new URISyntaxException(input, "Expected '://'", end);
		end = end + 3;
		
		start = end;
		end = scan(start, ":/");
		if (end == length)
			throw new URISyntaxException(input,
					"Unexpected end of URI looking for port or path");
		host = input.substring(start, end);
		
		if (input.charAt(end) == ':') { // get the port
			start = end;
			end = scan(start, "/");
			if (end == length)
				throw new URISyntaxException(input,
						"Unexpected end of URI looking for path");
			try {
				port = Integer.parseInt(input.substring(start + 1, end));
				if (port < 1 || port > 65535)
					throw new URISyntaxException(input, "port out of range", start);
			} catch (NumberFormatException nfe) {
				URISyntaxException use = new URISyntaxException(input,
						"Illegal port specification!", start);
				use.initCause(nfe);
				throw use;
			}
		}
		
		start = end;
		end = scan(start, "?#");
		path = input.substring(start, end);
		if (end == length)
			return;
		if (input.charAt(end) == '?') { // get the query
			start = end;
			end = scan(start, "#");
			path = input.substring(start, end);
		}
		if (end == length)
			return;
		
		if (input.charAt(end) == '#') { // get the fragment
			start = end;
			fragment = input.substring(start);
		}
	}

	// Scan forward from the given start position. Stop at the first char
	// in the stop string (in which case the index of the preceding char is
	// returned), or the end of the input string (in which case the length
	// of the input string is returned).
	private int scan(int start, String stop) {
		int p = start;
		int end = input.length();
		while (p < end) {
			char c = input.charAt(p);
			if (stop.indexOf(c) >= 0)
				break;
			p++;
		}
		return p;
	}

	public String getScheme() {
		return scheme;
	}

	public String getHost() {
		return host;
	}

	public int getPort() {
		return port;
	}

	public String getPath() {
		return path;
	}

	public String getQuery() {
		return query;
	}

	public String getFragment() {
		return fragment;
	}

	public String toString() {
		StringBuilder buff = new StringBuilder();
		buff.append(scheme).append("://");
		buff.append(host);
		if (port > -1)
			buff.append(":").append(port);
		buff.append(path);
		if (query != null)
			buff.append(query);
		if (fragment != null)
			buff.append(fragment);
		return buff.toString();
	}

}
