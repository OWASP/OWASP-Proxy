package org.owasp.httpclient;

import java.io.UnsupportedEncodingException;

public class AsciiString {

	public static String create(byte[] buff) {
		try {
			return new String(buff, "ASCII");
		} catch (UnsupportedEncodingException uee) {
			uee.printStackTrace();
			return null;
		}
	}

	public static String create(byte[] buff, int off, int len) {
		try {
			return new String(buff, off, len, "ASCII");
		} catch (UnsupportedEncodingException uee) {
			uee.printStackTrace();
			return null;
		}
	}

	public static byte[] getBytes(String string) {
		try {
			return string.getBytes("ASCII");
		} catch (UnsupportedEncodingException uee) {
			uee.printStackTrace();
			return null;
		}
	}
}
