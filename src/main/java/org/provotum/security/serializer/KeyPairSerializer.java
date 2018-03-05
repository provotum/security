package org.provotum.security.serializer;

import org.provotum.security.elgamal.PrivateKey;
import org.provotum.security.elgamal.PublicKey;

import java.math.BigInteger;
import java.util.StringTokenizer;

public class KeyPairSerializer {

    public static String serializePublicKey(PublicKey publicKey) {
        StringBuilder sb = new StringBuilder(2024);

        sb.append("P");
        sb.append(publicKey.getP());
        sb.append("Q");
        sb.append(publicKey.getQ());
        sb.append("G");
        sb.append(publicKey.getG());
        sb.append("H");
        sb.append(publicKey.getH());

        return sb.toString();
    }

    public static PublicKey publicKeyFromString(String publicKey) {
        StringTokenizer tokenizer = new StringTokenizer(publicKey, "PQGH");

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger p = new BigInteger(tokenizer.nextToken());

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger q = new BigInteger(tokenizer.nextToken());

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger g = new BigInteger(tokenizer.nextToken());

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger h = new BigInteger(tokenizer.nextToken());

        return new PublicKey(p, q, g, h);
    }

    public static String serializePrivateKey(PrivateKey privateKey) {
        StringBuilder sb = new StringBuilder(2024);

        sb.append("P");
        sb.append(privateKey.getP());
        sb.append("Q");
        sb.append(privateKey.getQ());
        sb.append("G");
        sb.append(privateKey.getG());
        sb.append("X");
        sb.append(privateKey.getX());

        return sb.toString();
    }

    public static PrivateKey privateKeyFromString(String privateKey) {
        StringTokenizer tokenizer = new StringTokenizer(privateKey, "PQGX");

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger p = new BigInteger(tokenizer.nextToken());

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger q = new BigInteger(tokenizer.nextToken());

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger g = new BigInteger(tokenizer.nextToken());

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided publicKey is invalid. No tokens found.");
        }

        BigInteger x = new BigInteger(tokenizer.nextToken());

        return new PrivateKey(p, q, g, x);
    }
}
