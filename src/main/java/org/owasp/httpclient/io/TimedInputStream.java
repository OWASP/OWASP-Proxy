package org.owasp.httpclient.io;

import java.io.IOException;
import java.io.InputStream;
import java.io.PushbackInputStream;

public class TimedInputStream extends EofNotifyingInputStream {

	private long first, last;

	public TimedInputStream(InputStream in) throws IOException {
		super(new PushbackInputStream(in));
		PushbackInputStream pbis = (PushbackInputStream) super.in;
		int i = pbis.read();
		first = System.currentTimeMillis();
		if (i > -1)
			pbis.unread(i);
	}

	protected void eof() {
		last = System.currentTimeMillis();
	}

	public long getFirstRead() {
		return first;
	}

	public long getLastRead() {
		return last;
	}
}
