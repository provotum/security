package org.provotum.security.serializer;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.additive.CipherText;

import java.math.BigInteger;
import java.util.StringTokenizer;

public class CipherTextSerializer {

    private static final int RADIX = 36;

    public static String serialize(CipherText cipherText) {
        StringBuilder sb = new StringBuilder();

        sb.append("G");
        sb.append(cipherText.getG().getValue().asBigInteger().toString(CipherTextSerializer.RADIX));
        sb.append("M");
        sb.append(cipherText.getG().getModulus().asBigInteger().toString(CipherTextSerializer.RADIX));

        sb.append("H");
        sb.append(cipherText.getH().getValue().asBigInteger().toString(CipherTextSerializer.RADIX));
        sb.append("M");
        sb.append(cipherText.getH().getModulus().asBigInteger().toString(CipherTextSerializer.RADIX));

        return sb.toString();
    }

    public static CipherText fromString(String ciphertext) {
        StringTokenizer tokenizer = new StringTokenizer(ciphertext, "GMH");

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. No tokens found.");
        }

        BigInteger bigGValue = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. Missing modulus for G.");
        }
        BigInteger bigGModulus = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. Missing value for H.");
        }

        BigInteger bigHValue = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. Missing modulus for H.");
        }
        BigInteger bigHModulus = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);


        ModInteger bigG = new ModInteger(bigGValue, bigGModulus);
        ModInteger bigH = new ModInteger(bigHValue, bigHModulus);


        return new CipherText(bigG, bigH, null);
    }

    public static CipherText fromString(String ciphertext, ModInteger random) {
        StringTokenizer tokenizer = new StringTokenizer(ciphertext, "GMH");

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. No tokens found.");
        }

        BigInteger bigGValue = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. Missing modulus for G.");
        }
        BigInteger bigGModulus = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. Missing value for H.");
        }

        BigInteger bigHValue = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);

        if (! tokenizer.hasMoreTokens()) {
            throw new IllegalArgumentException("Provided ciphertext is invalid. Missing modulus for H.");
        }
        BigInteger bigHModulus = new BigInteger(tokenizer.nextToken(), CipherTextSerializer.RADIX);


        ModInteger bigG = new ModInteger(bigGValue, bigGModulus);
        ModInteger bigH = new ModInteger(bigHValue, bigHModulus);


        return new CipherText(bigG, bigH, random);
    }

}
