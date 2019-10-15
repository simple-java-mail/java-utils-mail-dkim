package net.markenwerk.utils.mail.dkim;

import java.io.*;
import java.util.*;

class Utils {
	static String randomString(int length) {
	    Random r = new Random();
	    char[] chars = new char[length];
        for (int i = 0; i < length; i++) {
            int v = r.nextInt(0x60 + 6); // [0x20, 0x7f] + ctrl*6
            char c;
            if (v == 0) {
                c = '\r';
            } else if (v == 1) {
                c = '\n';
            } else if (v == 2) {
                c = ' ';
            } else if (v == 3) {
                c = '\f';
            } else if (v == 4) {
                c = '\b';
            } else if (v == 5) {
                c = '\t';
            } else {
                c = (char)(v - 6 + 0x20);   // [0x20, 0x7f]
            }
            chars[i] = c;
        }
        return new String(chars);
    }

    static byte[] read(File file) throws IOException {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        InputStream in = new BufferedInputStream(new FileInputStream(file));
        try {
            stream(in, out);
            out.flush();
            return out.toByteArray();
        } finally {
            safeClose(in);
        }
    }

    static void write(File file, byte[] bytes) throws IOException {
        OutputStream out = new BufferedOutputStream(new FileOutputStream(file));
        try {
            InputStream in = new ByteArrayInputStream(bytes);
            stream(in, out);
            out.flush();
        } finally {
            safeClose(out);
        }
    }
    
    private static void safeClose(OutputStream out) {
        try {
            out.close();
        } catch (IOException e) {
            // ignore
        }
    }    
    
    private static void safeClose(InputStream in) {
        try {
            in.close();
        } catch (IOException e) {
            // ignore
        }
    }
    
    private static void stream(InputStream in, OutputStream out) throws IOException {
        byte[] buff = new byte[1024];
        int len;
        while((len = in.read(buff)) > 0) {
            out.write(buff, 0, len);
        }
    }
}
