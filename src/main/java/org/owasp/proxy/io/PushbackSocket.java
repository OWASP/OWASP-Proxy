package org.owasp.proxy.io;

import java.io.IOException;
import java.io.OutputStream;
import java.io.PushbackInputStream;
import java.net.Socket;

public class PushbackSocket extends SocketWrapper {

	public PushbackSocket(Socket socket) throws IOException {
		super(socket, new ResettablePushbackInputStream(
				socket.getInputStream(), 128), socket.getOutputStream());
	}

	protected PushbackSocket(Socket socket, PushbackInputStream in,
			OutputStream out) throws IOException {
		super(socket, in, out);
	}

	public PushbackInputStream getInputStream() {
		return (PushbackInputStream) super.getInputStream();
	}

}
