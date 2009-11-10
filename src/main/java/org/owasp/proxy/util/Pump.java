package org.owasp.proxy.util;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.Socket;

public class Pump extends Thread {
	private InputStream in;
	private OutputStream out;

	public static void connect(Socket a, Socket b) throws IOException {
		Pump ab = new Pump(a.getInputStream(), b.getOutputStream());
		Pump ba = new Pump(b.getInputStream(), a.getOutputStream());
		ab.start();
		ba.start();
		while (ab.isAlive()) {
			try {
				ab.join();
			} catch (InterruptedException ie) {
			}
		}
		while (ba.isAlive()) {
			try {
				ba.join();
			} catch (InterruptedException ie) {
			}
		}
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
