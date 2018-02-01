package org.provotum.security.zeroknowledge.or;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;

public class OrProof {

    private ModInteger t0;
    private ModInteger s1;
    private ModInteger c1;

    private ModInteger y0;
    private ModInteger z0;

    private ModInteger y1;
    private ModInteger z1;

    private CipherText cipherText;
    private PublicKey publicKey;

    public OrProof(CipherText cipherText, PublicKey publicKey) {
        this.cipherText = cipherText;
        this.publicKey = publicKey;
    }

    public void commit() {
        // range [0, q]
        this.t0 = ModInteger.random(ModInteger.ONE.add(this.publicKey.getQ()));
        this.s1 = ModInteger.random(ModInteger.ONE.add(this.publicKey.getQ()));
        this.c1 = ModInteger.random(ModInteger.ONE.add(this.publicKey.getQ()));

        // y0 = g^t0
        this.y0 = this.publicKey.getG().pow(this.t0);
        // z0 = h^t0 (h = public key value)
        this.z0 = this.publicKey.getY().pow(this.t0);

        // y1 = g^s1*G^(-c1), G = g^r of public key
        this.y1 = this.publicKey.getG().pow(this.s1).multiply(cipherText.getC1().pow(this.c1.negate()));
        // z1 = h^s1(H/f)^(-c1)
        // TODO: check whether 2 is the actual domain of the message
        this.z1 = this.publicKey.getY().multiply((cipherText.getC2().divide(ModInteger.TWO)).pow(this.c1.negate()));
    }

    public Response challenge(ModInteger c) {
        if (c.compareTo(this.publicKey.getQ()) >= 0) {
            throw new IllegalArgumentException("Challenge c must be smaller than the public key's q, i.e. in the range [0, q)");
        }

        // c0 = c - c1
        ModInteger c0 = c.subtract(this.c1);
        // s0 = t0 + c0*r
        ModInteger s0 = this.t0.add(c0.multiply(this.cipherText.getR()));

        return new Response(s0, this.s1, c0, this.c1);
    }
}
