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
package org.owasp.proxy.httpclient;

import static org.junit.Assert.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.InputStream;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.proxy.httpclient.HttpClient;
import org.owasp.proxy.io.ChunkedInputStream;
import org.owasp.proxy.model.Conversation;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.test.TraceServer;

public class HttpClientTest {

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
		HttpClient client = new HttpClient();
		Request request = new Request();
		request.setSsl(false);
		request.setHost("localhost");
		request.setPort(9999);
		request.setMessage("GET /blah/blah?abc=def HTTP/1.0\r\nHost: localhost\r\n\r\n".getBytes());
		Conversation c = client.fetchResponse(request);
		System.out.println("Headers: " + (c.getResponseHeaderTime() - c.getRequestTime()));
		System.out.println("Content: " + (c.getResponseBodyTime() - c.getResponseHeaderTime()));
		System.out.write(c.getResponse().getMessage());
	}

	@Test
	public void testChunked() throws Exception {
		HttpClient client = new HttpClient();
		Request request = new Request();
		request.setSsl(false);
		request.setHost("www.google.co.za");
		request.setPort(80);
		request.setStartLine("GET /search?q=OWASP+Proxy&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a HTTP/1.1");
		request.addHeader("Host", "www.google.co.za");
		Conversation c = client.fetchResponse(request);
		System.out.println("Headers: " + (c.getResponseHeaderTime() - c.getRequestTime()));
		System.out.println("Content: " + (c.getResponseBodyTime() - c.getResponseHeaderTime()));
//		System.out.write(c.getResponse().getMessage());
//		System.out.print("<-The end");
		
		InputStream in = new ChunkedInputStream(new ByteArrayInputStream(c.getResponse().getContent()));
		byte[] buff = new byte[1024];
		int got;
		while ((got = in.read(buff)) > 0) {
			System.out.write(buff, 0, got);
		}
	}
}
