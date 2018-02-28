package org.provotum.security.serializer;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class ShaSerializer {

    /**
     * Serialize the given string to its SHA-512 representation.
     *
     * @param string The string to serialize.
     * @return Its SHA-512 representation.
     */
    public static String toSha512HexString(String string) {
        byte[] bytes;

        try {
            bytes = MessageDigest.getInstance("SHA-512").digest(string.getBytes(StandardCharsets.UTF_8));
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }

        StringBuilder sb = new StringBuilder(bytes.length * 2);

        for (byte b : bytes) {
            int j = (b & 0xff);

            // prepend a 0 if the value is below 16
            if (j < 16) {
                sb.append('0');
            }

            sb.append(Integer.toHexString(j));
        }

        return sb.toString();
    }
}
