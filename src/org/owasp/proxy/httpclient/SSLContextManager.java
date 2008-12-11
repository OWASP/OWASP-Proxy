package org.owasp.proxy.httpclient;

import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.Map;

import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.TrustManagerFactory;
import javax.net.ssl.X509TrustManager;

public class SSLContextManager {

	private Map<String, SSLContext> contexts = new HashMap<String, SSLContext>();

	private SSLContext defaultContext;

	private TrustManager[] permissiveTrustManagers = null;
	
	public SSLContextManager() {
		try {
			TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
			tmf.init((KeyStore) null);
			TrustManager[] managers = tmf.getTrustManagers();
			X509TrustManager manager = null;
			for (int i=0; i < managers.length; i++) {
				if (managers[i] instanceof X509TrustManager) {
					manager = new LoggingTrustManager((X509TrustManager) managers[i]);
					break;
				}
			}
			if (manager == null) {
				manager = new X509TrustManager() {
					public X509Certificate[] getAcceptedIssuers() {
						return null;
					}
					public void checkClientTrusted(X509Certificate[] certs, String authType) {
					}
					public void checkServerTrusted(X509Certificate[] certs, String authType) {
					}
				};
			}
			permissiveTrustManagers = new X509TrustManager[] { manager };
            defaultContext = SSLContext.getInstance("SSL");
            defaultContext.init(null, permissiveTrustManagers, new SecureRandom());
		} catch (NoSuchAlgorithmException nsae) {
			nsae.printStackTrace();
		} catch (KeyManagementException kme) {
			kme.printStackTrace();
		} catch (KeyStoreException kse) {
			kse.printStackTrace();
		}
	}

	public SSLContext getSSLContext(String host) {
		SSLContext context = contexts.get(host);
		if (context != null)
			return context;
		return defaultContext;
	}

	private static class LoggingTrustManager implements X509TrustManager {
		
		private X509TrustManager trustManager;
		
		public LoggingTrustManager(X509TrustManager trustManager) {
			this.trustManager = trustManager;
		}
		
		public X509Certificate[] getAcceptedIssuers() {
			return trustManager.getAcceptedIssuers();
		}

		public void checkClientTrusted(X509Certificate[] certs, String authType) {
			try {
				trustManager.checkClientTrusted(certs, authType);
			} catch (CertificateException ce) {
				ce.printStackTrace();
			}
		}

		public void checkServerTrusted(X509Certificate[] certs, String authType) {
			try {
				trustManager.checkServerTrusted(certs, authType);
			} catch (CertificateException ce) {
				ce.printStackTrace();
			}
		}
	}
	
}
