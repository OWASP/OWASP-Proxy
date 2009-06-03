package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

public class AutoGeneratingCertificateProviderTest {

	public static void main(String[] args) throws Exception {

		// KeyStore keystore = KeyStore.getInstance("PKCS12");
		// File file = new File(
		// "/Users/rogan/secure/Corsaire/localhost.corsaire.com.p12");
		// if (file.exists()) {
		// InputStream is = new FileInputStream(file);
		// keystore.load(is, "password".toCharArray());
		// Certificate[] chain = keystore
		// .getCertificateChain("localhost.corsaire.com");
		// System.out.println(Arrays.asList(chain));
		// System.exit(0);
		// } else {
		// System.err.println("filenotfound");
		// System.exit(0);
		// }

		CertificateProvider cp = new AutoGeneratingCertificateProvider(
				"/Users/rogan/workspace/owasp-proxy/keystore.jks", "JKS",
				"password".toCharArray());
		EncryptedConnectionHandler ech = new EncryptedConnectionHandler() {

			/*
			 * (non-Javadoc)
			 * 
			 * @see
			 * org.owasp.proxy.daemon.EncryptedConnectionHandler#handleConnection
			 * (java.net.Socket, java.net.InetSocketAddress, boolean)
			 */
			public void handleConnection(Socket socket,
					InetSocketAddress target, boolean ssl) throws IOException {
				InputStream is = socket.getInputStream();
				byte[] buff = new byte[1024];
				int got;
				while ((got = is.read(buff)) > -1) {
					System.out.write(buff, 0, got);
				}
			}

		};
		TargetedConnectionHandler sslch = new SSLConnectionHandler(cp, false,
				ech);
		Proxy proxy = new Proxy(new InetSocketAddress("localhost", 4433),
				sslch, new InetSocketAddress("www.fnb.co.za", 443));
		proxy.start();
		System.out.println("Started");
		System.in.read();
		proxy.stop();
		System.out.println("Stopped");
	}
}
