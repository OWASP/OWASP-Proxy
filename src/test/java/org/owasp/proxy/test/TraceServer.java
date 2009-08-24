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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.logging.Logger;

import org.owasp.proxy.daemon.ConnectionHandler;
import org.owasp.proxy.daemon.Server;
import org.owasp.proxy.httpclient.MessageFormatException;
import org.owasp.proxy.httpclient.MutableBufferedRequest;
import org.owasp.proxy.httpclient.MutableBufferedResponse;
import org.owasp.proxy.io.ChunkedOutputStream;
import org.owasp.proxy.io.CopyInputStream;
import org.owasp.proxy.util.AsciiString;
import org.owasp.proxy.util.MessageUtils;

public class TraceServer extends Server {

	private static Logger logger = Logger
			.getLogger(TraceServer.class.getName());

	private static boolean chunked = false;

	private static boolean verbose = false;

	private static String version = "HTTP/1.0";

	public TraceServer(int port) throws IOException {
		super(new InetSocketAddress("localhost", port), new CH());
	}

	public static void setChunked(boolean chunked) {
		TraceServer.chunked = chunked;
	}

	public static void setVerbose(boolean verbose) {
		TraceServer.verbose = verbose;
	}

	public static void setVersion(String version) {
		TraceServer.version = version;
	}

	private static class CH implements ConnectionHandler {

		public void handleConnection(Socket socket) {
			try {
				ByteArrayOutputStream copy = new ByteArrayOutputStream();
				CopyInputStream in = new CopyInputStream(socket
						.getInputStream(), copy);
				OutputStream out = socket.getOutputStream();

				if (verbose)
					logger.info("Connection: " + socket);
				boolean close = true;
				do {
					copy.reset();
					MutableBufferedRequest request = null;
					// read the whole header. Each line gets written into the
					// copy defined
					// above
					while (!"".equals(in.readLine()))
						;

					{
						byte[] headerBytes = copy.toByteArray();

						// empty request line, connection closed?
						if (headerBytes == null || headerBytes.length == 0)
							return;

						request = new MutableBufferedRequest.Impl();
						request.setHeader(headerBytes);
					}

					boolean expectContinue = "100-continue"
							.equalsIgnoreCase(request.getHeader("Expect"));
					if (expectContinue)
						out.write(AsciiString.getBytes(version
								+ " 100 Continue\r\n\r\n"));

					// Get the request content (if any) from the stream,
					copy.reset();
					if (MessageUtils.expectContent(request)
							&& MessageUtils.flushContent(request, in))
						request.setContent(copy.toByteArray());

					if (verbose) {
						logger.info(AsciiString.create(request.getHeader()));
						if (request.getContent() != null)
							logger.info(AsciiString
									.create(request.getContent()));
					}

					MutableBufferedResponse response = new MutableBufferedResponse.Impl();
					response.setStartLine(version + " 200 Ok");
					if (chunked) {
						response.setHeader("Transfer-Encoding", "chunked");
						ByteArrayOutputStream baos = new ByteArrayOutputStream();
						ChunkedOutputStream cos = new ChunkedOutputStream(baos,
								16);
						cos.write(request.getHeader());
						if (request.getContent() != null)
							out.write(request.getContent());
						cos.close();
						response.setContent(baos.toByteArray());
					} else {
						byte[] content = request.getContent() == null ? request
								.getHeader() : request.getContent();
						response.setContent(content);
					}
					if (verbose) {
						logger.info(AsciiString.create(response.getHeader()));
						if (response.getContent() != null)
							logger.info(AsciiString.create(response
									.getContent()));
					}

					out.write(response.getHeader());
					if (response.getContent() != null)
						out.write(response.getContent());
					out.flush();

					String connection = request.getHeader("Connection");
					if ("Keep-Alive".equalsIgnoreCase(connection)) {
						close = false;
					} else {
						close = true;
					}
				} while (!close);
			} catch (IOException e) {
				e.printStackTrace();
			} catch (MessageFormatException e) {
				e.printStackTrace();
			} finally {
				try {
					if (!socket.isClosed())
						socket.close();
				} catch (IOException ioe2) {
				}
			}
		}
	}

	public static void main(String[] args) throws Exception {
		TraceServer ts = new TraceServer(9999);
		TraceServer.setChunked(true);
		TraceServer.setVerbose(true);
		ts.start();
		System.out.println("Started");
		new BufferedReader(new InputStreamReader(System.in)).readLine();

		ts.stop();
		System.out.println("stopped");
	}
}
