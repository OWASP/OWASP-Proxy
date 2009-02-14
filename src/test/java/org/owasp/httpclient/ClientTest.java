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
package org.owasp.httpclient;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import java.io.InputStream;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.httpclient.io.ChunkedInputStream;
import org.owasp.proxy.test.TraceServer;

public class ClientTest {

	private static TraceServer ts = null;

	@BeforeClass
	public static void setUpBeforeClass() throws Exception {
		System.err.println("Running setupBeforeClass()");
		ts = new TraceServer(9999);
		Thread t = new Thread(ts);
		t.setDaemon(false);
		t.start();
	}

	@AfterClass
	public static void tearDownAfterClass() throws Exception {
		System.err.println("Running shutdown after class");
		ts.stop();
		Thread.sleep(1000);
		assertTrue("TraceServer shutdown failed!", ts.isStopped());
	}

	@Test
	public void testFetchResponse() throws Exception {
		Client client = new Client();
		client.connect("localhost", 9999, false);
		String request = "GET /blah/blah?abc=def HTTP/1.0\r\nHost: localhost\r\n\r\n";
		client.sendRequestHeader(request.getBytes());
		byte[] header = client.getResponseHeader();
		System.out.println("Header length: " + header.length);
		int got, read = 0;
		byte[] buff = new byte[1024];
		InputStream is = client.getResponseContent();
		while ((got = is.read(buff)) > 0)
			read = read + got;
		assertEquals(request.length(), read);
	}

	@Test
	public void testChunked() throws Exception {
		Client client = new Client();
		client.connect("www.google.co.za", 80, false);
		String request = "GET /search?q=OWASP+Proxy&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a HTTP/1.1\r\n"
				+ "Host : www.google.co.za\r\n\r\n";
		client.sendRequestHeader(request.getBytes());
		byte[] responseHeader = client.getResponseHeader();
		System.out.write(responseHeader);
		MessageHeader mh = new MessageHeader();
		mh.setHeader(responseHeader);
		InputStream is = client.getResponseContent();
		if ("chunked".equalsIgnoreCase(mh.getHeader("Transfer-Encoding")))
			is = new ChunkedInputStream(is);

		byte[] buff = new byte[1024];
		int got;
		while ((got = is.read(buff)) > 0) {
			System.out.write(buff, 0, got);
		}
		is.close();
	}
}
