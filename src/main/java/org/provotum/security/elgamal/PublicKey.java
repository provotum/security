package org.provotum.security.elgamal;

import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.provotum.security.arithmetic.ModInteger;

import java.math.BigInteger;

/**
 * An ElGamal public key.
 */
public class PublicKey {

    private ModInteger q;
    private ElGamalPublicKey publicKey;

    /**
     * @param publicKey The ElGamal public key to use.
     */
    public PublicKey(ElGamalPublicKey publicKey) {
        this.publicKey = publicKey;

        // q = (p - 1) / 2
        BigInteger q = this.publicKey.getParameters().getP().subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        this.q = new ModInteger(q);
    }

    /**
     * The public key value, i.e. <code>h := y := (g^x) mod p</code>.
     *
     * @return The public key value <b>y</b> aka <b>h</b>.
     */
    public ModInteger getH() {
        return new ModInteger(this.publicKey.getY(), this.publicKey.getParameters().getP());
    }

    /**
     * A value representing the base generator.
     *
     * @return The base generator <b>g</b>.
     */
    public ModInteger getG() {
        return new ModInteger(this.publicKey.getParameters().getG(), this.publicKey.getParameters().getP());
    }

    /**
     * A value representing the prime modulus <b>p</b>.
     * <p>
     * <code>p = 2*q + 1</code>
     *
     * @return The prime modulus <b>p</b>.
     */
    public ModInteger getP() {
        return new ModInteger(this.publicKey.getParameters().getP());
    }

    /**
     * A value representing the prime <b>q</b> corresponding to <b>p</b>.
     * <p>
     * <code>q = (p - 1)/ 2</code>
     *
     * @return The corresponding prime <b>q</b>.
     */
    public ModInteger getQ() {
        return q;
    }
}
