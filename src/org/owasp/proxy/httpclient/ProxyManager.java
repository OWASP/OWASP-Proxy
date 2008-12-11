package org.owasp.proxy.httpclient;

import org.owasp.proxy.model.URI;


public interface ProxyManager {

	String findProxyForUrl(URI uri);
	
}
