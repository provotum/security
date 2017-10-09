package org.provotum.security.elgamal;

import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.provotum.security.arithmetic.ModInteger;

public class ExtendedElGamalPrivateKey {

    private ElGamalPrivateKey privateKey;

    /**
     * @param privateKey The ElGamal private key to use.
     */
    public ExtendedElGamalPrivateKey(ElGamalPrivateKey privateKey) {
        this.privateKey = privateKey;
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
