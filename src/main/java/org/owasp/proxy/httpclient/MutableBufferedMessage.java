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

public interface MutableBufferedMessage extends BufferedMessage,
		MutableMessageHeader {

	/**
	 * @param content
	 */
	void setContent(byte[] content);

	/**
	 * Allows the caller to avoid dealing with Transfer-Encoding and
	 * Content-Encoding details.
	 * 
	 * The content provided will have Chunking and Gzip, etc encodings applied
	 * as specified by the message header, before being set as the message
	 * content.
	 * 
	 * @param content
	 * @throws MessageFormatException
	 */
	void setDecodedContent(byte[] content) throws MessageFormatException;

}
