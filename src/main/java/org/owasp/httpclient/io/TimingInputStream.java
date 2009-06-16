package org.owasp.httpclient.io;

import java.io.IOException;
import java.io.InputStream;

import org.owasp.httpclient.MutableResponseHeader;

public class TimingInputStream extends EofNotifyingInputStream {

	private boolean first = true;

	private MutableResponseHeader response;

	public TimingInputStream(InputStream in, MutableResponseHeader response)
			throws IOException {
		super(in);
		this.response = response;
	}

	protected void eof() {
		response.setContentCompletedTime(System.currentTimeMillis());
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.io.EofNotifyingInputStream#read()
	 */
	@Override
	public int read() throws IOException {
		int got = super.read();
		if (first) {
			response.setContentStartedTime(System.currentTimeMillis());
			first = false;
		}
		return got;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see org.owasp.httpclient.io.EofNotifyingInputStream#read(byte[], int,
	 * int)
	 */
	@Override
	public int read(byte[] b, int off, int len) throws IOException {
		int got = super.read(b, off, len);
		if (first) {
			response.setContentStartedTime(System.currentTimeMillis());
			first = false;
		}
		return got;
	}

}
