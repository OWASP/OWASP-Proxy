package org.owasp.proxy.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Pump extends Thread {
	private InputStream in;
	private OutputStream out;

	public static void connect(Socket a, Socket b) throws IOException {
		new Pump(a.getInputStream(), b.getOutputStream()).start();
		new Pump(b.getInputStream(), a.getOutputStream()).start();
	}

	public Pump(InputStream in, OutputStream out) {
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
