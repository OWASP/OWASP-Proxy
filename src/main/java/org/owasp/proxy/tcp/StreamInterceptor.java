package org.owasp.proxy.tcp;

import java.io.IOException;

public interface StreamInterceptor<C, S> {

	void connected(StreamHandle clientServer, StreamHandle serverClient,
			C clientLabel, S serverLabel);

	void received(StreamHandle handle, byte[] b, int off, int len);

	void readException(StreamHandle handle, IOException ioe);

	void inputClosed(StreamHandle handle);

}
