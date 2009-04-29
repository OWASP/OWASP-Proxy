package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;
import java.util.logging.Logger;

import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.proxy.io.PushbackSocket;

public abstract class SSLProxy extends Proxy {

	private Logger logger = Logger.getLogger(getClass().getName());

	public enum SSL {
		NEVER, ALWAYS, AUTO
	};

	private SSL ssl;

	public SSLProxy(InetSocketAddress listen, InetSocketAddress target,
			SOCKS socks, SSL ssl) throws IOException {
		super(listen, target, socks);
		if (ssl == null)
			ssl = SSL.AUTO;
		this.ssl = ssl;
	}

	@Override
	protected final void handleConnection(Socket socket,
			InetSocketAddress target) {
		PushbackSocket pbs;
		try {
			if (socket instanceof PushbackSocket) {
				pbs = (PushbackSocket) socket;
			} else {
				pbs = new PushbackSocket(socket);
			}
			boolean ssl = false;
			if (this.ssl.equals(SSL.AUTO)) {
				// check if it is an SSL connection
				byte[] sniff = sniff(pbs, 4);
				if (sniff == null) // connection closed
					return;

				if (isSSL(sniff))
					ssl = true;
			} else if (this.ssl.equals(SSL.ALWAYS))
				ssl = true;

			if (ssl) {
				try {
					SSLSocketFactory factory = getSSLSocketFactory(target);
					if (factory == null)
						return;
					handleConnection(negotiateSsl(pbs, factory), target, true);
				} catch (GeneralSecurityException gse) {
					logger
							.warning("Error negotiating SSL: "
									+ gse.getMessage());
					return;
				}
			} else {
				handleConnection(pbs, target, false);
			}
		} catch (IOException ioe) {
			logger.fine(ioe.getMessage());
			return;
		}
	}

	protected abstract void handleConnection(Socket socket,
			InetSocketAddress target, boolean ssl);

	private SSLSocketFactory sslSocketFactory = null;

	protected SSLSocketFactory getSSLSocketFactory(InetSocketAddress target)
			throws GeneralSecurityException {
		if (sslSocketFactory == null) {
			try {
				DefaultCertificateProvider cp = new DefaultCertificateProvider();
				sslSocketFactory = cp.getSocketFactory(null, -1);
			} catch (IOException ioe) {
				throw new GeneralSecurityException(ioe);
			}
		}
		return sslSocketFactory;
	}

	private byte[] sniff(PushbackSocket socket, int len) throws IOException {
		PushbackInputStream in = socket.getInputStream();
		byte[] sniff = new byte[len];
		int read = 0, attempt = 0;
		do {
			int got = in.read(sniff, read, sniff.length - read);
			if (got == -1)
				return null;
			read += got;
			attempt++;
		} while (read < sniff.length && attempt < sniff.length);
		if (read < sniff.length)
			throw new IOException("Failed to read " + len
					+ " bytes in as many attempts!");
		in.unread(sniff);
		return sniff;
	}

	private boolean isSSL(byte[] sniff) {
		for (int i = 0; i < sniff.length; i++)
			if (sniff[i] == 0x03)
				return true;
		return false;
	}

	protected SSLSocket negotiateSsl(Socket socket, SSLSocketFactory factory)
			throws GeneralSecurityException, IOException {
		SSLSocket sslsock = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		sslsock.setUseClientMode(false);
		return sslsock;
	}

}
