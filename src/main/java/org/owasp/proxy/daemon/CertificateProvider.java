package org.owasp.proxy.daemon;

import java.io.IOException;

import javax.net.ssl.SSLSocketFactory;

public interface CertificateProvider {

	SSLSocketFactory getSocketFactory(String host, int port) throws IOException;

}
