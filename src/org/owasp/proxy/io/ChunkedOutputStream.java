package org.owasp.proxy.io;

import java.io.OutputStream;
import java.io.FilterOutputStream;
import java.io.IOException;

/**
 *
 * @author  Rogan Dawes
 */
public class ChunkedOutputStream extends FilterOutputStream {
    boolean closed = false;
    
    private int maxChunkSize = Integer.MAX_VALUE;
    
    public ChunkedOutputStream(OutputStream out) {
        super(out);
    }

    public ChunkedOutputStream(OutputStream out, int chunkSize) {
    	super(out);
    	maxChunkSize = chunkSize;
    }
    
    @Override
    public void write(int b) throws IOException {
        out.write("1\r\n".getBytes());
        out.write(b);
        out.write("\r\n".getBytes());
    }
    
    @Override
    public void write(byte[] b, int off, int len) throws IOException {
    	do {
    		int chunk = Math.min(len, maxChunkSize);
            out.write((Integer.toString(chunk, 16) + "\r\n").getBytes());
            out.write(b, off, chunk);
            out.write("\r\n".getBytes());
    		off += chunk;
    		len -= chunk;
    	} while (len > 0);
    }
    
    @Override
    public void close() throws IOException {
    	if (closed) return;
        out.write("0\r\n\r\n".getBytes());
        flush();
        super.close();
    }
    
}
