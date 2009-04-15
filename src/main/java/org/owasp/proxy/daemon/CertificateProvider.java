package org.owasp.proxy.daemon;

import java.io.IOException;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLSocketFactory;

public interface CertificateProvider {

	SSLSocketFactory getSocketFactory(String host, int port)
			throws IOException, GeneralSecurityException;

}
