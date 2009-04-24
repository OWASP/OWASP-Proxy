package org.owasp.proxy.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class SocketPipe {

	private Socket a, b;

	public SocketPipe(Socket a, Socket b) {
		this.a = a;
		this.b = b;
	}

	public void connect() {
		try {
			new Pipe(a.getInputStream(), b.getOutputStream()).start();
			new Pipe(b.getInputStream(), a.getOutputStream()).start();
		} catch (IOException ioe) {
			try {
				a.close();
			} catch (IOException ignore) {
			}
			try {
				b.close();
			} catch (IOException ignore) {
			}
		}
	}

	private static class Pipe extends Thread {
		private InputStream in;
		private OutputStream out;

		public Pipe(InputStream in, OutputStream out) {
			this.in = in;
			this.out = out;
			setDaemon(true);
		}

		public void run() {
			try {
				byte[] buff = new byte[4096];
				int got;
				while ((got = in.read(buff)) > -1)
					out.write(buff, 0, got);
			} catch (IOException ignore) {
			} finally {
				try {
					in.close();
				} catch (IOException ignore) {
				}
				try {
					out.close();
				} catch (IOException ignore) {
				}
			}
		}
	}
}
