package org.owasp.webscarab.model;


public class Conversation {

	private long id;
	
	private Request request;
	
	private Response response;
	
	private String connection;
	
	private long requestTime, responseHeaderTime, responseBodyTime;
	
	public Conversation() {
	}
	
	public long getId() {
		return id;
	}
	
	public void setId(long id) {
		this.id = id;
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
	
	public void setResponseBodyTime(long time) {
		responseBodyTime = time;
	}
	
	public long getResponseBodyTime() {
		return responseBodyTime;
	}
	
}
