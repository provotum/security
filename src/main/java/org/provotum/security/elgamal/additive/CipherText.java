package org.provotum.security.elgamal.additive;

import org.provotum.security.api.ICipherText;
import org.provotum.security.arithmetic.ModInteger;

public class CipherText implements ICipherText<CipherText> {

    private ModInteger c1;
    private ModInteger c21;
    private ModInteger c22;

    private ModInteger r;

    public CipherText(ModInteger c1, ModInteger c21, ModInteger c22, ModInteger r) {
        this.c1 = c1;
        this.c21 = c21;
        this.c22 = c22;
        this.r = r;
    }

    /**
     * Multiply the given cipher text with this instance: In terms
     * of arithmetic, adds the given cipher text's clear value to this instance's value.
     * <p>
     * <pre>
     *   E(m) = (g^r, g^m * h^r), with
     * </pre>
     * g = generator
     * m = message
     * h = g^x i.e. the public key whereas x = private key
     * r = [0, q-1]
     * <p>
     * <pre>
     * E(m1) * E(m2) = ( g^(r1 + r2), g^(m1 + m2) * h^(r1 + r2) )
     *               = E(m1 + m2)
     * </pre>
     *
     * @param cipherText The cipher text to add using multiplication.
     * @return The resulting cipher text
     */
    public CipherText multiply(CipherText cipherText) {
        // TODO: check public keys for equality

        // E(m) = (c1, c21 * c22) = (g^r, g^m * h^r)
        //
        // g^r1 * g^r2
        this.c1 = this.c1.multiply(cipherText.c1);
        // g^m1 * g^m2
        this.c21 = this.c21.multiply(cipherText.c21);
        // h^r1 * h^r2
        this.c22 = this.c22.multiply(cipherText.c22);

        this.r = this.r.add(cipherText.getR());

        return this;
    }

    public ModInteger getC1() {
        return this.c1;
    }

    public ModInteger getC2() {
        return this.c21.multiply(this.c22);
    }

    public ModInteger getR() {
        return this.r;
    }
}
