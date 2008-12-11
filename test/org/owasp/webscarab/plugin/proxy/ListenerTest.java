package org.owasp.webscarab.plugin.proxy;

import static org.junit.Assert.*;

import java.io.IOException;
import java.io.PrintStream;
import java.net.InetAddress;

import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.owasp.webscarab.httpclient.HttpClient;
import org.owasp.webscarab.httpclient.ProxyManager;
import org.owasp.webscarab.model.Conversation;
import org.owasp.webscarab.model.MessageFormatException;
import org.owasp.webscarab.model.Request;
import org.owasp.webscarab.model.Response;
import org.owasp.webscarab.model.URI;
import org.owasp.webscarab.test.TraceServer;

public class ListenerTest {

	private static TraceServer ts;
	
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

//	@Test
	public void testListenerStartStop() throws Exception {
		Listener l = new Listener(InetAddress.getByAddress(new byte[] {127,0,0,1}), 9998);
		Thread t = new Thread(l);
		t.setDaemon(true);
		t.start();
		
		Thread.sleep(1000);
		
		l.stop();
		Thread.sleep(1000);
		assertTrue("Listener didn't exit", l.isStopped());
	}

//	@Test
	public void testRun() throws Exception {
		Listener l = new Listener(InetAddress.getByAddress(new byte[] {127,0,0,1}), 9998);
		ProxMon pm = new ProxMon();
		l.setProxyMonitor(pm);
		Thread t = new Thread(l);
		t.setDaemon(true);
		t.start();
		
		HttpClient client = new HttpClient();
		client.setProxyManager(new ProxyManager() {
			public String findProxyForUrl(URI uri) {
				return "PROXY localhost:9998";
			}
		});
		
		Request request = new Request();
		request.setHeader("GET http://localhost:9999/ HTTP/1.0\r\n\r\n".getBytes());
		// Conversation c = 
		client.fetchResponse(request);
		// System.out.write(c.getResponse().getMessage());
		
		
		request.setMessage("POST http://localhost:9999/ HTTP/1.0\r\nContent-Length: 15\r\n\r\n123456789012345".getBytes());
		// c = 
		client.fetchResponse(request);
		// System.out.write(c.getResponse().getMessage());
		
		request.setMessage("POST http://localhost:999 HTTP/1.0\r\nContent-Length: 15\r\n\r\n123456789012345".getBytes());
		// c = 
		client.fetchResponse(request);
		// System.out.write(c.getResponse().getMessage());
		
		l.stop();
		Thread.sleep(1000);
		assertTrue("Listener didn't exit", l.isStopped());
	}

	@Test
	public void testChunked() throws Exception {
		ts.setChunked(true);
		Listener l = new Listener(InetAddress.getByAddress(new byte[] {127,0,0,1}), 9998);
		ProxMon pm = new ProxMon();
		l.setProxyMonitor(pm);
		Thread t = new Thread(l);
		t.setDaemon(true);
		t.start();
		
		HttpClient client = new HttpClient();
		client.setProxyManager(new ProxyManager() {
			public String findProxyForUrl(URI uri) {
				return "PROXY localhost:9998";
			}
		});
		
		Request request = new Request();
		request.setStartLine("GET http://localhost:9999/search?q=webscarab&ie=utf-8&oe=utf-8&aq=t&rls=org.mozilla:en-US:official&client=firefox-a HTTP/1.1");
		request.addHeader("Host", "www.google.co.za");

		Conversation c = client.fetchResponse(request);
		System.out.write(c.getResponse().getMessage());
		
		l.stop();
		Thread.sleep(1000);
		assertEquals("response did not match request", request.getMessage(), c.getResponse().getContent());
	}

	private static class ProxMon extends ProxyMonitor {

		@Override
		public Response errorFetchingResponseHeader(Request request, Exception e) throws MessageFormatException {
			try {
				System.err.println("Error fetching response header: \n");
				System.err.write(request.getMessage());
				e.printStackTrace(new PrintStream(System.err));
			} catch (IOException ioe) {
			}
			return null;
		}

		@Override
		public Response errorFetchingResponseContent(Conversation conversation, Exception e) throws MessageFormatException {
			try {
				System.err.println("Error fetching response content: \n");
				System.err.write(conversation.getRequest().getMessage());
				System.err.println();
				System.err.write(conversation.getResponse().getMessage());
				System.err.println();
				e.printStackTrace(new PrintStream(System.err));
			} catch (IOException ioe) {
			}
			return null;
		}

		@Override
		public Response errorReadingRequest(Request request, Exception e) throws MessageFormatException {
			try {
				System.err.println("Error reading request: \n");
				if (request != null)
					System.err.write(request.getMessage());
				e.printStackTrace(new PrintStream(System.err));
			} catch (IOException ioe) {
			}
			return null;
			
		}

		@Override
		public void errorWritingResponseToBrowser(
				Conversation conversation, Exception e) throws MessageFormatException {
			try {
				System.err
						.println("Error writing response to browser: \nRequest:\n");
				System.err.write(conversation.getRequest().getMessage());
				System.err.println("Response: \n");
				System.err.write(conversation.getResponse().getMessage());
				e.printStackTrace(new PrintStream(System.err));
			} catch (IOException ioe) {
			}
		}

		@Override
		public void wroteResponseToBrowser(Conversation conversation) throws MessageFormatException {
			try {
				int resp = conversation.getResponse().getMessage().length;
				long time = conversation.getResponseBodyTime() - conversation.getRequestTime();
				
				System.out.println(conversation.getRequest().getStartLine()
						+ " : " + conversation.getResponse().getStatus()
						+ " - " + resp + " bytes in " + time + " (" + (resp*1000/time) + " bps)");
			} catch (MessageFormatException mfe) {
			}
		}

	}
}
