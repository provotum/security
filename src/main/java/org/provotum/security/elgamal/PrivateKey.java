package org.provotum.security.elgamal;

import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.provotum.security.arithmetic.ModInteger;

import java.math.BigInteger;

/**
 * An ElGamal private key.
 */
public class PrivateKey {

    private final ModInteger p;
    private final ModInteger q;
    private final ModInteger g;
    private final ModInteger x;

    /**
     * @param privateKey The ElGamal private key to use.
     */
    public PrivateKey(ElGamalPrivateKey privateKey) {
        this.p = new ModInteger(privateKey.getParameters().getP());
        // q = (p - 1) / 2
        this.q = new ModInteger(privateKey.getParameters().getP().subtract(BigInteger.ONE).divide(BigInteger.valueOf(2)));
        this.g = new ModInteger(privateKey.getParameters().getG());
        this.x = new ModInteger(privateKey.getX());
    }

    /**
     * @param p The prime modulus p.
     * @param q The number q wrt. to p: (p - 1) / 2
     * @param g The generator g.
     * @param x The private key x.
     */
    public PrivateKey(BigInteger p, BigInteger q, BigInteger g, BigInteger x) {
        this.p = new ModInteger(p);
        this.q = new ModInteger(q);
        this.g = new ModInteger(g);
        this.x = new ModInteger(x);
    }

    /**
     * The private key value.
     *
     * @return The private key.
     */
    public ModInteger getX() {
        return this.x;
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
     * A value representing the component of p <b>q</b>.
     * <p>
     * <code>q = (p - 1) / 2</code>
     *
     * @return The component <b>q</b>.
     */
    public ModInteger getQ() {
        return q;
    }

    /**
     * A value representing the base generator g.
     *
     * @return The base generator <b>g</b>.
     */
    public ModInteger getG() {
        return this.g;
    }

    @Override
    public int hashCode() {
        return this.x.hashCode() | this.g.hashCode() | this.p.hashCode() | this.q.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return (this == o) || (o instanceof PrivateKey) &&
            this.x.equals(((PrivateKey) o).x) &&
            this.g.equals(((PrivateKey) o).g) &&
            this.p.equals(((PrivateKey) o).p) &&
            this.q.equals(((PrivateKey) o).q);
    }
}
