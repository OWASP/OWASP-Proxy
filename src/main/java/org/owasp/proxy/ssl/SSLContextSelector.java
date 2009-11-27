package org.owasp.proxy.ssl;

import java.net.InetSocketAddress;

import javax.net.ssl.SSLContext;

public interface SSLContextSelector {

	SSLContext select(InetSocketAddress target);

}
