package org.owasp.httpclient;

import java.io.IOException;
import java.net.InetAddress;

public interface AddressResolver {

	InetAddress getAddress(String host) throws IOException;

}
