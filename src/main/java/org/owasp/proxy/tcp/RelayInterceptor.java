package org.owasp.proxy.tcp;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Handles one side of the communications between client and target, reading
 * from the InputStream, and notifying the StreamInterceptor.
 * 
 * @author rogan
 * 
 */
class RelayInterceptor<C, S> extends Thread implements StreamHandle {

	private StreamInterceptor<C, S> interceptor;
	private InputStream in;
	private OutputStream out;
	private boolean done = false;
	private Object lock = new Object();

	private Runnable closer = null;

	public RelayInterceptor(StreamInterceptor<C, S> interceptor,
			InputStream in, OutputStream out) {
		this.interceptor = interceptor;
		this.in = in;
		this.out = out;
		setName("Interceptor");
		setDaemon(true);
	}

	public void setCloseHandler(Runnable closer) {
		this.closer = closer;
	}

	public void run() {
		try {
			byte[] buff = new byte[4096];
			int got;
			while ((got = in.read(buff)) > -1 && !done) {
				interceptor.received(this, buff, 0, got);
			}
		} catch (IOException ioe) {
			interceptor.readException(this, ioe);
		} finally {
			interceptor.inputClosed(this);
		}
		try {
			while (!done) {
				synchronized (lock) {
					lock.wait(1000);
				}
			}
		} catch (InterruptedException ie) {
			// we're done, return
		}
		if (closer != null)
			closer.run();
	}

	public void write(byte[] b, int off, int len) throws IOException {
		out.write(b, off, len);
	}

	public void close() {
		try {
			out.flush();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		done = true;
		synchronized (lock) {
			lock.notify();
		}
	}
}