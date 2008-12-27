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

import java.io.InputStream;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Proxy;
import java.net.URL;
import java.net.URLConnection;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.proxy.test.TraceServer;

public class ListenerTest {

	private static TraceServer ts;
	
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

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.err.println("Running shutdown after class");
		ts.stop();
		Thread.sleep(1000);
		assertTrue("TraceServer shutdown failed!", ts.isStopped());
	}

	@Test
	public void testListenerStartStop() throws Exception {
		Listener l = new Listener(InetAddress.getByAddress(new byte[] {127,0,0,1}), 9998);
		l.start();
		
		Thread.sleep(1000);
		
		l.stop();
		assertTrue("Listener didn't exit", l.isStopped());
	}

	@Test
	public void testRun() throws Exception {
		Listener l = new Listener(9998);
		ProxyMonitor pm = new LoggingProxyMonitor();
		l.setProxyMonitor(pm);
		l.start();
		
		Proxy p = new Proxy(Proxy.Type.HTTP, new InetSocketAddress("localhost", 9998));
		
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
			
//			request.setPort(999);
//			request.setMessage("POST / HTTP/1.0\r\nContent-Length: 15\r\n\r\n123456789012345".getBytes());
//			// c = 
//			client.fetchResponse(request);
//			// System.out.write(c.getResponse().getMessage());
			
		} finally {
			
			l.stop();
			Thread.sleep(1000);
		}
	}

	@Test
	public void testChunked() throws Exception {
		ts.setChunked(true);
		Listener l = new Listener(9998);
		ProxyMonitor pm = new LoggingProxyMonitor();
		l.setProxyMonitor(pm);
		l.start();
		
//		try {
//			Request request = new Request();
//			request.setSsl(false);
//			request.setHost("localhost");
//			request.setPort(9999);
//			request.setStartLine("GET /search?q=OWASP+Proxy&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a HTTP/1.1");
//			request.addHeader("Host", "www.google.co.za");
//	
//			Conversation c = client.fetchResponse(request);
//			System.out.write(c.getResponse().getMessage());
//			assertEquals("response did not match request", request.getMessage(), c.getResponse().getContent());
//		} finally {
			l.stop();
//			assertTrue("Listener didn't exit", l.isStopped());
//		}
	}

}
