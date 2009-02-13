package org.owasp.httpclient;

import java.net.InetSocketAddress;

import javax.net.ssl.SSLContext;

public interface SSLContextSelector {

	SSLContext select(InetSocketAddress target);

}
