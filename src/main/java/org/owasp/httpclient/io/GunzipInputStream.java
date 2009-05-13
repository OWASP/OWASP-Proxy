package org.owasp.httpclient.io;

import java.io.IOException;
import java.io.InputStream;
import java.util.zip.GZIPInputStream;

/*
 * This is a kind of "noop" class. All it does is provide a convenient way of
 * renaming an existing JRE class that is poorly named, and clashes with a desired name
 * of a new class to be implemented.
 */
public class GunzipInputStream extends GZIPInputStream {

	public GunzipInputStream(InputStream in) throws IOException {
		super(in);
	}

	public GunzipInputStream(InputStream in, int size) throws IOException {
		super(in, size);
	}

}
