package org.owasp.proxy.tcp;

import java.io.InputStream;
import java.io.OutputStream;

public class StreamRelay<C, S> implements Runnable {

	private RelayInterceptor<C, S> cs, sc;

	/**
	 * This class reads information from the client InputStream, and writes it
	 * to the server OutputStream via interceptor, and reads data from the
	 * server InputStream and writes it to the client OutputStream via
	 * interceptor.
	 * 
	 * @param interceptor
	 *            the interceptor that processes the data
	 * @param clientLabel
	 *            a label for the interceptor to use to identify the client
	 * @param ci
	 *            the client InputStream
	 * @param co
	 *            the client OutputStream
	 * @param serverLabel
	 *            a label for the interceptor to use to identify the server
	 * @param si
	 *            the server InputStream
	 * @param so
	 *            the server OutputStream
	 */
	public StreamRelay(StreamInterceptor<C, S> interceptor, C clientLabel,
			InputStream ci, OutputStream co, S serverLabel, InputStream si,
			OutputStream so) {
		cs = new RelayInterceptor<C, S>(interceptor, ci, so);
		cs.setName("Client");
		sc = new RelayInterceptor<C, S>(interceptor, si, co);
		sc.setName("Server");
		interceptor.connected(cs, sc, clientLabel, serverLabel);
	}

	public void setCloseHandlers(Runnable cch, Runnable sch) {
		cs.setCloseHandler(cch);
		sc.setCloseHandler(sch);
	}

	public void run() {
		cs.start();
		sc.start();
		while (cs.isAlive() || sc.isAlive()) {
			try {
				if (cs.isAlive())
					cs.join(100);
				if (sc.isAlive())
					sc.join(100);
			} catch (InterruptedException ie) {
				return;
			}
		}
	}
}
