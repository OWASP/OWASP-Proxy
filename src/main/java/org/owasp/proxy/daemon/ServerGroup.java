package org.owasp.proxy.daemon;

import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

public class ServerGroup {

	private static List<InetAddress> addrs = null;

	static {
		addrs = new ArrayList<InetAddress>();
		try {
			Enumeration<NetworkInterface> ni = NetworkInterface
					.getNetworkInterfaces();
			while (ni.hasMoreElements()) {
				Enumeration<InetAddress> ia = ni.nextElement()
						.getInetAddresses();
				while (ia.hasMoreElements())
					addrs.add(ia.nextElement());
			}
		} catch (SocketException se) {
			se.printStackTrace();
		}
	}

	private List<InetSocketAddress> servers;

	public synchronized void addServer(InetSocketAddress listen) {
		servers.add(listen);
	}

	public synchronized void removeServer(InetSocketAddress listen) {
		servers.remove(listen);
	}

	private static boolean isLocalAddress(InetAddress target) {
		return addrs.contains(target);
	}

	public synchronized boolean wouldAccept(InetSocketAddress target) {
		for (InetSocketAddress listen : servers) {
			if (listen.getPort() == target.getPort()) { // maybe
				if (listen.getAddress().equals(target.getAddress()))
					return true;
				else if (listen.getAddress().isAnyLocalAddress()
						&& isLocalAddress(target.getAddress()))
					return true;
			}
		}
		return false;
	}

}
