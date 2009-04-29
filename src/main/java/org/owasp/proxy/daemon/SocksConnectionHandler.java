package org.owasp.proxy.daemon;

import java.io.IOException;
import java.io.PushbackInputStream;
import java.net.InetSocketAddress;
import java.net.Socket;

import org.owasp.proxy.io.PushbackSocket;

public class SocksConnectionHandler implements TargetedConnectionHandler {

	private TargetedConnectionHandler next;

	boolean detect;

	public SocksConnectionHandler(TargetedConnectionHandler next, boolean detect) {
		this.next = next;
		this.detect = detect;
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

	/*
	 * (non-Javadoc)
	 * 
	 * @see
	 * org.owasp.proxy.daemon.ConnectionHandler#handleConnection(java.net.Socket
	 * , java.net.InetSocketAddress)
	 */
	public void handleConnection(Socket socket, InetSocketAddress target)
			throws IOException {
		boolean socks = true;
		if (detect) {
			PushbackSocket pbs = socket instanceof PushbackSocket ? (PushbackSocket) socket
					: new PushbackSocket(socket);
			socket = pbs;
			// check if it is a SOCKS request
			byte[] sniff = sniff(pbs, 1);
			if (sniff == null) // connection closed
				return;

			if (!(sniff[0] == 4 || sniff[0] == 5)) // SOCKS v4 or V5
				socks = false;
		}

		if (socks) {
			SocksProtocolHandler sp = new SocksProtocolHandler(socket, null);
			target = sp.handleConnectRequest();
		}

		next.handleConnection(socket, target);
	}

}
