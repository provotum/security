package org.provotum.security.elgamal;

import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.provotum.security.arithmetic.ModInteger;

import java.math.BigInteger;

/**
 * An ElGamal public key.
 */
public class PublicKey {

    private final ModInteger p;
    private final ModInteger q;
    private final ModInteger h;
    private final ModInteger g;

    /**
     * @param publicKey The ElGamal public key to use.
     */
    public PublicKey(ElGamalPublicKey publicKey) {
        this.p = new ModInteger(publicKey.getParameters().getP());
        // q = (p - 1) / 2
        BigInteger q = publicKey.getParameters().getP().subtract(BigInteger.ONE).divide(BigInteger.valueOf(2));
        this.q = new ModInteger(q);
        this.g = new ModInteger(publicKey.getParameters().getG(), publicKey.getParameters().getP());
        this.h = new ModInteger(publicKey.getY(), publicKey.getParameters().getP());
    }

    /**
     * @param p The prime modulus p.
     * @param q The number q wrt. to p: (p - 1) / 2
     * @param g The generator g.
     * @param h The public key value, i.e. <code>h := y := (g^x) mod p</code>.
     */
    public PublicKey(BigInteger p, BigInteger q, BigInteger g, BigInteger h) {
        this.p = new ModInteger(p);
        this.q = new ModInteger(q);
        this.g = new ModInteger(g, p);
        this.h = new ModInteger(h, p);
    }

    /**
     * The public key value, i.e. <code>h := y := (g^x) mod p</code>.
     *
     * @return The public key value <b>y</b> aka <b>h</b>.
     */
    public ModInteger getH() {
        return this.h;
    }

    /**
     * A value representing the base generator.
     *
     * @return The base generator <b>g</b>.
     */
    public ModInteger getG() {
        return this.g;
    }

    /**
     * A value representing the prime modulus <b>p</b>.
     * <p>
     * <code>p = 2*q + 1</code>
     *
     * @return The prime modulus <b>p</b>.
     */
    public ModInteger getP() {
        return this.p;
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

    @Override
    public int hashCode() {
        return this.h.hashCode() | this.g.hashCode() | this.p.hashCode() | this.q.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return (this == o) || (o instanceof PublicKey) &&
            this.h.equals(((PublicKey) o).h) &&
            this.g.equals(((PublicKey) o).g) &&
            this.p.equals(((PublicKey) o).p) &&
            this.q.equals(((PublicKey) o).q);
    }
}
