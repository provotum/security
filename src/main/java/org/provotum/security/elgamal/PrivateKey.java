package org.provotum.security.elgamal;

import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.provotum.security.arithmetic.ModInteger;

import java.math.BigInteger;

public class PrivateKey {

    private ElGamalPrivateKey privateKey;
    private ModInteger q;

    /**
     * @param privateKey The ElGamal private key to use.
     */
    public PrivateKey(ElGamalPrivateKey privateKey) {
        this.privateKey = privateKey;

        // q = (p - 1) / 2
        this.q = new ModInteger(this.privateKey.getParameters().getP().subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)));
    }

    public ModInteger partialDecrypt(CipherText cipherText) {
        return cipherText.getG().pow(new ModInteger(this.privateKey.getX(), this.q.getValue()));
    }

    /**
     * The private key value.
     *
     * @return The private key.
     */
    public ModInteger getX() {
        return new ModInteger(this.privateKey.getX());
    }

    /**
     * A value representing the prime modulus <b>p</b>.
     * <p>
     * <code>p = 2*q + 1</code>
     *
     * @return The prime modulus <b>p</b>.
     */
    public ModInteger getP() {
        return new ModInteger(this.privateKey.getParameters().getP());
    }

    /**
     * A value representing the message modulus.
     *
     * @return The message modulus <b>f</b>.
     */
    public ModInteger getG() {
        return new ModInteger(this.privateKey.getParameters().getG());
    }
}
