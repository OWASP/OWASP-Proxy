package org.owasp.proxy.httpclient;

import java.io.IOException;
import java.net.InetAddress;

public interface Resolver {

	InetAddress getAddress(String host) throws IOException;
	
}
