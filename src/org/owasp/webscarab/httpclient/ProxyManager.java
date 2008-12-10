package org.owasp.webscarab.httpclient;

import org.owasp.webscarab.model.URI;


public interface ProxyManager {

	String findProxyForUrl(URI uri);
	
}
