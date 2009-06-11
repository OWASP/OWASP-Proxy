package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.GeneralSecurityException;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.owasp.httpclient.SSLContextSelector;
import org.owasp.proxy.io.PushbackSocket;

public class SSLConnectionHandler implements TargetedConnectionHandler {

	private SSLContextSelector sslContextSelector;

	private boolean detect;

	private EncryptedConnectionHandler next;

	public SSLConnectionHandler(SSLContextSelector sslContextSelector,
			boolean detect, EncryptedConnectionHandler next) {
		this.sslContextSelector = sslContextSelector;
		this.detect = detect;
		this.next = next;
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

	protected SSLSocketFactory getSSLSocketFactory(InetSocketAddress target)
			throws IOException, GeneralSecurityException {
		SSLContext sslContext = sslContextSelector == null ? null
				: sslContextSelector.select(target);
		return sslContext == null ? null : sslContext.getSocketFactory();
	}

	protected SSLSocket negotiateSSL(Socket socket, SSLSocketFactory factory)
			throws GeneralSecurityException, IOException {
		SSLSocket sslsock = (SSLSocket) factory.createSocket(socket, socket
				.getInetAddress().getHostName(), socket.getPort(), true);
		sslsock.setUseClientMode(false);
		return sslsock;
	}

	protected boolean isSSL(byte[] sniff) {
		for (int i = 0; i < sniff.length; i++)
			if (sniff[i] == 0x03)
				return true;
		return false;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ConnectionHandler#handleConnection(java.net.Socket
	 * , java.net.InetSocketAddress)
	 */
	public void handleConnection(Socket socket, InetSocketAddress target)
			throws IOException {
		boolean ssl = true;
		if (detect) {
			PushbackSocket pbs = socket instanceof PushbackSocket ? (PushbackSocket) socket
					: new PushbackSocket(socket);
			socket = pbs;
			// check if it is an SSL connection
			byte[] sniff = sniff(pbs, 4);
			if (sniff == null) // connection closed
				return;

			if (!isSSL(sniff))
				ssl = false;
		}

		if (ssl) {
			try {
				SSLSocketFactory factory = getSSLSocketFactory(target);
				if (factory == null)
					return;
				socket = negotiateSSL(socket, factory);
				if (socket == null)
					return;
			} catch (GeneralSecurityException gse) {
				IOException ioe = new IOException(
						"Error obtaining the certificate");
				ioe.initCause(gse);
				throw ioe;
			}
		}

		next.handleConnection(socket, target, ssl);
	}
}
