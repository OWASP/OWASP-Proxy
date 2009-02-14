package org.owasp.proxy.httpclient;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.Socket;
import java.net.SocketAddress;

import org.owasp.proxy.daemon.Listener;

public class HttpClient extends org.owasp.httpclient.Client {

	@Override
	protected void checkLoop(SocketAddress target) throws IOException {
		// FIXME - this is looking a bit clunky
		SocketAddress[] listeners = Listener.getListeners();
		if (target instanceof InetSocketAddress) {
			InetSocketAddress dst = (InetSocketAddress) target;
			for (int i = 0; i < listeners.length; i++) {
				if (listeners[i] instanceof InetSocketAddress) {
					InetSocketAddress isa = (InetSocketAddress) listeners[i];
					if (isa.getAddress().isAnyLocalAddress()) {
						if (NetworkInterface.getByInetAddress(dst.getAddress()) != null
								&& dst.getPort() == isa.getPort())
							throw new IOException(
									"Loop detected! Request target is a local Listener");
					} else if (target.equals(listeners[i]))
						throw new IOException(
								"Loop detected! Request target is a local Listener");
				}
			}
		}
	}

	public Socket getSocket() {
		return socket;
	}

}
