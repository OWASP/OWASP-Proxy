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
package org.owasp.proxy.test;

import java.io.BufferedReader;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;

import org.owasp.proxy.io.ChunkedOutputStream;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.model.Request;
import org.owasp.proxy.model.Response;

public class TraceServer implements Runnable {
	
	private Thread thread;
	
	private ServerSocket socket;
	
	private boolean chunked = false;
	
	private boolean verbose = false;
	
	public TraceServer(int port) throws IOException {
		try {
			InetAddress address = InetAddress.getByAddress(new byte[] {127, 0, 0, 1});
			socket = new ServerSocket(port, 20, address);
			socket.setReuseAddress(true);
			socket.setSoTimeout(500);
		} catch (UnknownHostException uhe) {
			// should never happen
		}
	}
	
	public void setChunked(boolean chunked) {
		this.chunked = chunked;
	}
	
	public void setVerbose(boolean verbose) {
		this.verbose = verbose;
	}
	
	public void run() {
		try {
			synchronized(this) {
				if (thread == null) {
					thread = Thread.currentThread();
				} else {
					throw new RuntimeException("Multiple threads! " + thread + " and " + Thread.currentThread());
				}
			}
	        while (!Thread.interrupted()) {
	            try {
	                CH ch = new CH(socket.accept());
	                Thread thread = new Thread(ch);
	                thread.setDaemon(true);
	                thread.start();
	            } catch (SocketTimeoutException ste) {
	            }
	        }
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		try {
			if (socket != null && !socket.isClosed())
				socket.close();
		} catch (IOException ioe) {
			ioe.printStackTrace();
		}
		synchronized(this) {
			thread = null;
			notifyAll();
		}
	}

	public void stop() {
		if (thread != null && thread.isAlive()) {
			thread.interrupt();
			synchronized(this) {
				while (!isStopped()) {
					try {
						wait();
					} catch (InterruptedException ie) {}
				}
			}
		}
	}
	
	public synchronized boolean isStopped() {
		return thread == null || !thread.isAlive();
	}
	
	private class CH implements Runnable {
		
		private Socket socket;
		
		public CH(Socket socket) {
			this.socket = socket;
		}
		
		public void run() {
			try {
				ByteArrayOutputStream copy = new ByteArrayOutputStream();
				CopyInputStream in = new CopyInputStream(socket.getInputStream(), copy);
				OutputStream out = socket.getOutputStream();
				
				if (verbose)
					System.err.println("Connection: " + socket);
				boolean close = true;
				do {
                	copy.reset();
            		Request request = null;
            		// read the whole header. Each line gets written into the copy defined
            		// above
            		while (!"".equals(in.readLine()))
            			;
            		
            		{
	            		byte[] headerBytes = copy.toByteArray();
	            		
	                    // empty request line, connection closed?
	            		if (headerBytes == null || headerBytes.length == 0)
	            			return;
	            		
	            		request = new Request();
	                    request.setHeader(headerBytes);
            		}
            		
                    // Get the request content (if any) from the stream,
                    if (Request.flushContent(request, in, null))
                    	request.setMessage(copy.toByteArray());
	            	
                    if (verbose)
                    	System.out.write(request.getMessage());
                    
                    Response response = new Response();
                    response.setStartLine("HTTP/1.1 200 Ok");
                    if (chunked) {
                    	response.setHeader("Transfer-Encoding", "chunked");
                    	ByteArrayOutputStream baos = new ByteArrayOutputStream();
                    	ChunkedOutputStream cos = new ChunkedOutputStream(baos, 16);
                    	cos.write(request.getMessage());
                    	cos.close();
                    	response.setContent(baos.toByteArray());
                    } else {
                    	response.setContent(request.getMessage());
                    }
                    if (verbose)
                    	System.out.write(response.getMessage());
                    
                    out.write(response.getMessage());
                    out.flush();

                    String connection = request.getHeader("Connection");
	                if ("Keep-Alive".equalsIgnoreCase(connection)) {
	                    close = false;
	                } else {
	                    close = true;
	                }
				} while (!close);
			} catch (Exception e) {
				e.printStackTrace();
			} finally {
				try {
					if (!socket.isClosed())
						socket.close();
				} catch (IOException ioe2) {}
			}
		}
	}
	
	public static void main(String[] args) throws Exception {
		TraceServer ts = new TraceServer(9999);
		ts.setChunked(true);
		ts.setVerbose(true);
		Thread t = new Thread(ts);
		t.start();
		System.out.println("Started");
		new BufferedReader(new InputStreamReader(System.in)).readLine();
		
		ts.stop();
		System.out.println("stopped");
	}
}
