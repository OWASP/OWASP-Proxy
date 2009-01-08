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
package org.owasp.proxy.model;

public class Conversation {

	private static int sequence = 1;

	private int id;

	private Request request;

	private Response response;

	private String connection;

	private long requestTime, responseHeaderTime, responseContentTime;

	public static synchronized void resetSequence() {
		sequence = 1;
	}

	public Conversation() {
		synchronized (Conversation.class) {
			id = sequence++;
		}
	}

	public Conversation(int id) {
		synchronized (Conversation.class) {
			this.id = id;
			if (id > sequence)
				sequence = id + 1;
		}
	}

	public int getId() {
		return id;
	}

	public void setRequest(Request request) {
		this.request = request;
	}

	public Request getRequest() {
		return this.request;
	}

	public void setResponse(Response response) {
		this.response = response;
	}

	public Response getResponse() {
		return this.response;
	}

	public String getConnection() {
		return this.connection;
	}

	public void setConnection(String connection) {
		this.connection = connection;
	}

	public void setRequestTime(long time) {
		requestTime = time;
	}

	public long getRequestTime() {
		return requestTime;
	}

	public void setResponseHeaderTime(long time) {
		responseHeaderTime = time;
	}

	public long getResponseHeaderTime() {
		return responseHeaderTime;
	}

	public void setResponseContentTime(long time) {
		responseContentTime = time;
	}

	public long getResponseContentTime() {
		return responseContentTime;
	}

}
