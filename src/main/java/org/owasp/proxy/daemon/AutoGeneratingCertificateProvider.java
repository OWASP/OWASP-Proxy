package org.owasp.proxy.daemon;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Vector;
import java.util.logging.Logger;

import javax.net.ssl.KeyManager;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.X509KeyManager;

import sun.security.util.ObjectIdentifier;
import sun.security.x509.AlgorithmId;
import sun.security.x509.AuthorityKeyIdentifierExtension;
import sun.security.x509.BasicConstraintsExtension;
import sun.security.x509.CertAndKeyGen;
import sun.security.x509.CertificateAlgorithmId;
import sun.security.x509.CertificateExtensions;
import sun.security.x509.CertificateIssuerName;
import sun.security.x509.CertificateSerialNumber;
import sun.security.x509.CertificateSubjectName;
import sun.security.x509.CertificateValidity;
import sun.security.x509.CertificateVersion;
import sun.security.x509.CertificateX509Key;
import sun.security.x509.ExtendedKeyUsageExtension;
import sun.security.x509.KeyIdentifier;
import sun.security.x509.KeyUsageExtension;
import sun.security.x509.NetscapeCertTypeExtension;
import sun.security.x509.SubjectKeyIdentifierExtension;
import sun.security.x509.X500Name;
import sun.security.x509.X500Signer;
import sun.security.x509.X509CertImpl;
import sun.security.x509.X509CertInfo;

public class AutoGeneratingCertificateProvider implements CertificateProvider {

	private static Logger logger = Logger
			.getLogger(AutoGeneratingCertificateProvider.class.getName());

	private static final String CA = "CA";

	private static final String SIGALG = "SHA1withRSA";

	private String filename;

	private KeyStore keystore;

	private char[] password;

	private Map<String, SSLContext> contextCache = new HashMap<String, SSLContext>();

	private X500Name caName = new X500Name("CA", "OWASP Custom CA", "OWASP",
			"OWASP", "OWASP", "OWASP");

	public AutoGeneratingCertificateProvider(String filename, String type,
			char[] password) throws GeneralSecurityException, IOException {
		this.filename = filename;
		this.password = password;
		keystore = KeyStore.getInstance(type);
		File file = new File(filename);
		if (filename == null) {
			logger
					.info("No keystore provided, keys and certificates will be transient!");
		}
		if (file.exists()) {
			logger.fine("Loading keys from " + filename);
			InputStream is = new FileInputStream(file);
			keystore.load(is, password);
			if (keystore.getKey(CA, password) == null) {
				logger.warning("Keystore does not contain an entry for '" + CA
						+ "'");
			}
		} else {
			logger.info("Generating CA key");
			keystore.load(null, password);
			generateCA();
		}
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.CertificateProvider#getSocketFactory(java.lang
	 * .String, int)
	 */
	public synchronized SSLSocketFactory getSocketFactory(String host, int port)
			throws IOException, GeneralSecurityException {
		SSLContext sslcontext = contextCache.get(host);
		if (sslcontext == null) {
			if (!keystore.containsAlias(host))
				generate(host);
			sslcontext = SSLContext.getInstance("SSLv3");
			HostKeyManager km = new HostKeyManager(host);
			sslcontext.init(new KeyManager[] { km }, null, null);
			contextCache.put(host, sslcontext);
		}
		return sslcontext.getSocketFactory();
	}

	private void saveKeystore() {
		if (filename == null)
			return;
		try {
			OutputStream out = new FileOutputStream(filename);
			keystore.store(out, password);
			out.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} catch (GeneralSecurityException gse) {
			gse.printStackTrace();
		}
	}

	private void generateCA() throws GeneralSecurityException, IOException {
		CertAndKeyGen keygen = new CertAndKeyGen("RSA", "SHA1WithRSA");
		keygen.generate(1024);

		PrivateKey key = keygen.getPrivateKey();

		java.security.cert.X509Certificate certificate = keygen
				.getSelfCertificate(caName, 5L * 365L * 24L * 60L * 60L * 1000L);

		certificate.checkValidity();
		keystore.setKeyEntry(CA, key, password,
				new Certificate[] { certificate });
		saveKeystore();
	}

	private void generate(String cname) throws GeneralSecurityException {
		try {
			PrivateKey caKey = (PrivateKey) keystore.getKey(CA, password);
			PublicKey caPubKey = keystore.getCertificate(CA).getPublicKey();
			Certificate[] caCertChain = keystore.getCertificateChain(CA);

			PrivateKey privKey = caKey;
			PublicKey pubKey = caPubKey;

			if (false) {
				CertAndKeyGen keygen = new CertAndKeyGen("RSA", "SHA1WithRSA");
				keygen.generate(1024);
				privKey = keygen.getPrivateKey();
				pubKey = keygen.getPublicKey();
			}

			Signature signature = Signature.getInstance(SIGALG);

			signature.initSign(caKey);
			X500Signer issuer = new X500Signer(signature, caName);

			Date begin = new Date();
			Date ends = new Date(begin.getTime() + 365L * 24L * 60L * 60L
					* 1000L);
			CertificateValidity valid = new CertificateValidity(begin, ends);
			X500Name subject = new X500Name(cname, caName
					.getOrganizationalUnit(), caName.getOrganization(), caName
					.getCountry());

			X509CertInfo info = new X509CertInfo();
			// Add all mandatory attributes
			info.set(X509CertInfo.VERSION, new CertificateVersion(
					CertificateVersion.V3));
			info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(
					(int) (begin.getTime() / 1000)));
			AlgorithmId algID = issuer.getAlgorithmId();
			info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(
					algID));
			info.set(X509CertInfo.SUBJECT, new CertificateSubjectName(subject));
			info.set(X509CertInfo.KEY, new CertificateX509Key(pubKey));
			info.set(X509CertInfo.VALIDITY, valid);
			info.set(X509CertInfo.ISSUER, new CertificateIssuerName(issuer
					.getSigner()));

			// add Extensions
			CertificateExtensions ext = getCertificateExtensions(pubKey,
					caPubKey);
			info.set(X509CertInfo.EXTENSIONS, ext);

			X509CertImpl cert = new X509CertImpl(info);
			cert.sign(caKey, SIGALG);

			Certificate[] certChain = new Certificate[caCertChain.length + 1];
			System.arraycopy(caCertChain, 0, certChain, 1, caCertChain.length);
			certChain[0] = cert;

			keystore.setKeyEntry(cname, privKey, password, certChain);

			saveKeystore();
		} catch (IOException e) {
			throw new CertificateEncodingException("generate: "
					+ e.getMessage(), e);
		}
	}

	private CertificateExtensions getCertificateExtensions(PublicKey pubKey,
			PublicKey caPubKey) throws IOException {
		CertificateExtensions ext = new CertificateExtensions();

		ext.set(SubjectKeyIdentifierExtension.NAME,
				new SubjectKeyIdentifierExtension(new KeyIdentifier(pubKey)
						.getIdentifier()));

		ext.set(AuthorityKeyIdentifierExtension.NAME,
				new AuthorityKeyIdentifierExtension(
						new KeyIdentifier(caPubKey), null, null));

		// Basic Constraints
		ext.set(BasicConstraintsExtension.NAME, new BasicConstraintsExtension(
		/* isCritical */true, /* isCA */
		false, /* pathLen */Integer.MAX_VALUE));

		// Netscape Cert Type Extension
		boolean[] ncteOk = new boolean[8];
		ncteOk[0] = true; // SSL_CLIENT
		ncteOk[1] = true; // SSL_SERVER
		NetscapeCertTypeExtension ncte = new NetscapeCertTypeExtension(ncteOk);
		ncte = new NetscapeCertTypeExtension(false, ncte.getExtensionValue());
		ext.set(NetscapeCertTypeExtension.NAME, ncte);

		// Key Usage Extension
		boolean[] kueOk = new boolean[9];
		kueOk[0] = true;
		kueOk[2] = true;
		// "digitalSignature", // (0),
		// "nonRepudiation", // (1)
		// "keyEncipherment", // (2),
		// "dataEncipherment", // (3),
		// "keyAgreement", // (4),
		// "keyCertSign", // (5),
		// "cRLSign", // (6),
		// "encipherOnly", // (7),
		// "decipherOnly", // (8)
		// "contentCommitment" // also (1)
		KeyUsageExtension kue = new KeyUsageExtension(kueOk);
		ext.set(KeyUsageExtension.NAME, kue);

		// Extended Key Usage Extension
		int[] serverAuthOidData = { 1, 3, 6, 1, 5, 5, 7, 3, 1 };
		ObjectIdentifier serverAuthOid = new ObjectIdentifier(serverAuthOidData);
		int[] clientAuthOidData = { 1, 3, 6, 1, 5, 5, 7, 3, 2 };
		ObjectIdentifier clientAuthOid = new ObjectIdentifier(clientAuthOidData);
		Vector<ObjectIdentifier> v = new Vector<ObjectIdentifier>();
		v.add(serverAuthOid);
		v.add(clientAuthOid);
		ExtendedKeyUsageExtension ekue = new ExtendedKeyUsageExtension(false, v);
		ext.set(ExtendedKeyUsageExtension.NAME, ekue);

		return ext;

	}

	private class HostKeyManager implements X509KeyManager {

		private String host;

		public HostKeyManager(String host) {
			this.host = host;
		}

		public String chooseClientAlias(String[] keyType, Principal[] issuers,
				Socket socket) {
			throw new UnsupportedOperationException("Not implemented");
		}

		public String chooseServerAlias(String keyType, Principal[] issuers,
				Socket socket) {
			return host;
		}

		public X509Certificate[] getCertificateChain(String alias) {
			X509Certificate[] chain = null;
			try {
				Certificate[] certs = keystore.getCertificateChain(alias);
				if (certs != null) {
					chain = new X509Certificate[certs.length];
					for (int i = 0; i < certs.length; i++) {
						chain[i] = (X509Certificate) certs[i];
					}
				}
			} catch (KeyStoreException e) {
				throw new RuntimeException("Internal error: " + e.getMessage(),
						e);
			}
			return chain;
		}

		public String[] getClientAliases(String keyType, Principal[] issuers) {
			throw new UnsupportedOperationException("Not implemented");
		}

		public PrivateKey getPrivateKey(String alias) {
			PrivateKey pk = null;
			try {
				pk = (PrivateKey) keystore.getKey(alias, password);
				if (pk == null)
					throw new RuntimeException(
							"Internal error: private key for " + alias
									+ " is null!");
			} catch (KeyStoreException e) {
				throw new RuntimeException("Internal error: " + e.getMessage(),
						e);
			} catch (NoSuchAlgorithmException e) {
				throw new RuntimeException("Internal error: " + e.getMessage(),
						e);
			} catch (UnrecoverableKeyException e) {
				throw new RuntimeException("Internal error: " + e.getMessage(),
						e);
			}
			return pk;
		}

		public String[] getServerAliases(String keyType, Principal[] issuers) {
			return new String[] { host };
		}

	}
}
