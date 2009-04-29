/*
 *  This file is part of the OWASP Proxy, a free intercepting HTTP proxy
 *  library.
 *  Copyright (C) 2008  Rogan Dawes <rogan@dawes.za.net>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License version 2 as 
 *  published by the Free Software Foundation.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 */
package org.owasp.proxy.daemon;

import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.Socket;
import java.net.SocketAddress;
import java.net.SocketException;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.net.URLConnection;

import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Ignore;
import org.junit.Test;
import org.owasp.proxy.daemon.Proxy.SOCKS;
import org.owasp.proxy.daemon.SSLProxy.SSL;
import org.owasp.proxy.test.TraceServer;

public class DefaultHttpProxyTest {

	private static TraceServer ts;

	InetSocketAddress listen;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.err.println("Running setupBeforeClass()");
		try {
			ts = new TraceServer(9999);
			Thread t = new Thread(ts);
			t.setDaemon(true);
			t.start();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	@Before
	public void setup() throws Exception {
		listen = new InetSocketAddress("localhost", 9998);
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.err.println("Running shutdown after class");
		ts.stop();
		Thread.sleep(1000);
		assertTrue("TraceServer shutdown failed!", ts.isStopped());
	}

	@Test
	public void testListenerStartStop() throws Exception {
		DefaultHttpProxy proxy = new DefaultHttpProxy(listen, null, SOCKS.AUTO,
				SSL.AUTO);
		proxy.start();

		Thread.sleep(1000);

		proxy.stop();
		assertTrue("Listener didn't exit", proxy.isStopped());
	}

	@Test
	public void testRun() throws Exception {
		DefaultHttpProxy proxy = new DefaultHttpProxy(listen, null, SOCKS.AUTO,
				SSL.AUTO);
		proxy.start();

		Proxy p = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost",
				9998));

		try {
			URL url = new URL("http://localhost:9999/");
			URLConnection uc = url.openConnection(p);
			uc.connect();
			InputStream is = uc.getInputStream();
			byte buff[] = new byte[1024];
			int got;
			while ((got = is.read(buff)) > 0) {
				System.out.write(buff, 0, got);
			}
			is.close();

			uc = url.openConnection(p);
			uc.setRequestProperty("Content-Length", "15");
			uc.setDoOutput(true);
			uc.connect();
			OutputStream os = uc.getOutputStream();
			os.write("123456789012345".getBytes());
			os.close();
			is = uc.getInputStream();
			while ((got = is.read(buff)) > 0) {
				System.out.write(buff, 0, got);
			}
			is.close();

			// request.setPort(999);
			// request.setMessage("POST / HTTP/1.0\r\nContent-Length: 15\r\n\r\n123456789012345".getBytes());
			// // c =
			// client.fetchResponse(request);
			// // System.out.write(c.getResponse().getMessage());

		} finally {
			proxy.stop();
		}
	}

	@Test
	@Ignore("needs internet access")
	public void testChunked() throws Exception {
		ts.setChunked(true);
		DefaultHttpProxy proxy = new DefaultHttpProxy(listen, null, SOCKS.AUTO,
				SSL.AUTO);
		proxy.start();

		// try {
		// Request request = new Request();
		// request.setSsl(false);
		// request.setHost("localhost");
		// request.setPort(9999);
		// request.setStartLine("GET /search?q=OWASP+Proxy&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a HTTP/1.1");
		// request.addHeader("Host", "www.google.co.za");
		//	
		// Conversation c = client.fetchResponse(request);
		// System.out.write(c.getResponse().getMessage());
		// assertEquals("response did not match request", request.getMessage(),
		// c.getResponse().getContent());
		// } finally {
		proxy.stop();
		// assertTrue("Listener didn't exit", l.isStopped());
		// }
	}

	/*
	 * Tests to make sure that the listener correctly closes idle sockets. This
	 * test ensures that completely unused sockets get closed, e.g. the result
	 * of "telnet proxy port" + doing nothing
	 */
	@Test
	public void testInitialTimeout() throws Exception {
		DefaultHttpProxy proxy = new DefaultHttpProxy(listen, null, SOCKS.AUTO,
				SSL.AUTO);
		proxy.setSocketTimeout(1000);
		proxy.start();

		try {
			SocketAddress addr = new InetSocketAddress("localhost", 9998);
			Socket s = new Socket(Proxy.NO_PROXY);
			s.connect(addr);
			Thread.sleep(2500);
			OutputStream os = s.getOutputStream();
			os.write("GET http://localhost:9999/ HTTP/1.0\r\n\r\n".getBytes());
			os.flush();
			s.setSoTimeout(500);
			InputStream is = s.getInputStream();
			int got;
			byte[] buff = new byte[1024];
			try {
				while ((got = is.read(buff)) > 0) {
					System.out.write(buff, 0, got);
				}
			} catch (SocketTimeoutException expected) {
			} catch (SocketException expected) {
				return;
			}
			s.close();
			fail("Should not get here if the socket was timed out correctly!");
		} catch (IOException ioe) {
			ioe.printStackTrace();
		} finally {
			proxy.stop();
			assertTrue("Listener didn't exit", proxy.isStopped());
		}
	}

	/*
	 * tests to make sure that idle sockets get closed. This test ensures that
	 * "used" sockets get closed after the timeout period.
	 */
	@Test
	public void testSecondTimeout() throws Exception {
		ts.setVersion("HTTP/1.1");
		DefaultHttpProxy proxy = new DefaultHttpProxy(listen, null, SOCKS.AUTO,
				SSL.AUTO);
		proxy.setSocketTimeout(1000);
		proxy.start();

		try {
			SocketAddress addr = new InetSocketAddress("localhost", 9998);
			Socket s = new Socket(Proxy.NO_PROXY);
			s.connect(addr);
			OutputStream os = s.getOutputStream();
			os
					.write("GET http://localhost:9999/ HTTP/1.1\r\nHost: localhost\r\n\r\n"
							.getBytes());
			os.flush();
			InputStream is = s.getInputStream();
			s.setSoTimeout(500);
			int got;
			byte[] buff = new byte[1024];
			try {
				while ((got = is.read(buff)) > 0)
					;
				fail("Socket closed unexpectedly!");
			} catch (SocketTimeoutException expected) {
				System.out
						.println("Finished reading the first response via timeout");
			}
			System.out.println("Submitting second request\n\n");
			try {
				Thread.sleep(2000);
				os
						.write("GET http://localhost:9999/ HTTP/1.1\r\nHost: localhost\r\n\r\n"
								.getBytes());
				os.flush();
				try {
					if ((got = is.read(buff)) > 0) {
						System.out.write(buff, 0, got);
						fail("Expected the socket to be closed");
					} else {
						return;
					}
				} catch (SocketTimeoutException unexpected) {
					throw unexpected;
				} catch (SocketException expected) {
					System.err.println("Got expected socket exception: "
							+ expected.getMessage());
					return;
				}
				s.close();
				fail("Should not get here if the socket was timed out correctly!");
			} catch (IOException ioe) {
				ioe.printStackTrace();
			} finally {
				if (s != null && !s.isClosed())
					try {
						s.close();
					} catch (IOException ignored) {
					}
			}
		} finally {
			proxy.stop();
			assertTrue("Listener didn't exit", proxy.isStopped());
		}
	}

}
