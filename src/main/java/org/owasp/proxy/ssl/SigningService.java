package org.owasp.proxy.ssl;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.security.auth.x500.X500Principal;

public interface SigningService {
	public X509Certificate sign(X500Principal subject, PublicKey pubKey, X500Principal issuer, PublicKey caPubKey,
																	PrivateKey caKey, Date begin, Date ends, BigInteger serialNo, X509Certificate baseCrt)
																	throws GeneralSecurityException;
}
