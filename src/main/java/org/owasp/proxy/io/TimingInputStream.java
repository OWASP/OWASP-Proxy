package org.owasp.proxy.io;

import java.io.IOException;
import java.io.InputStream;

import org.owasp.proxy.http.MutableResponseHeader;

public class TimingInputStream extends EofNotifyingInputStream {

	private MutableResponseHeader response;

	public TimingInputStream(InputStream in, MutableResponseHeader response)
			throws IOException {
		super(in);
		this.response = response;
	}

	protected void eof() {
		response.setContentTime(System.currentTimeMillis());
	}

}
