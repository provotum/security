package org.provotum.security.elgamal.proof.interactive;

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
        // range [0, q - 1]
        this.t0 = ModInteger.random(this.publicKey.getQ());
        this.s1 = ModInteger.random(this.publicKey.getQ());
        this.c1 = ModInteger.random(this.publicKey.getQ());

        // TODO rme: remove this!
        // TODO: check whether it should be actually p instead of q
        this.t0 = new ModInteger(0, this.publicKey.getP());
        this.s1 = new ModInteger(1, this.publicKey.getP());
        this.c1 = new ModInteger(1, this.publicKey.getP());

        // y0 = g^t0
        this.y0 = this.publicKey.getG().pow(this.t0);
        // z0 = h^t0 (h = public key value)
        this.z0 = this.publicKey.getH().pow(this.t0);

        // y1 = g^s1*G^(-c1), G = g^r of public key
        this.y1 = this.publicKey.getG().pow(this.s1).multiply(cipherText.getG().pow(this.c1.negate()));
        // z1 = h^s1(H/f)^(-c1)
        // TODO: check whether 2 is the actual domain of the message
        this.z1 = this.publicKey.getH().pow(this.s1).multiply((cipherText.getH().divide(ModInteger.TWO)).pow(this.c1.negate()));
    }

    public Response challenge(ModInteger c) {
        if (c.compareTo(this.publicKey.getP()) >= 0) {
            throw new IllegalArgumentException("Challenge c must be smaller than the public key's q, i.e. in the range [0, q)");
        }

        // c0 = c - c1
        ModInteger c0 = c.subtract(this.c1);
        // s0 = t0 + c0*r
        ModInteger s0 = this.t0.add(c0.multiply(this.cipherText.getR()));

        return new Response(s0, this.s1, c0, this.c1);
    }

    public boolean verify(ModInteger c, Response response) {
        // g^s0 === y0 * G^c0, G = g^r of public key
        ModInteger left1 = this.publicKey.getG().pow(response.getS0());
        ModInteger right1 = this.y0.multiply(this.cipherText.getG().pow(response.getC0()));
        boolean challenge1Valid = left1.equals(right1);

        // h^s0 === z0 * H^c0
        ModInteger left2 = this.publicKey.getH().pow(response.getS0());
        ModInteger right2 = this.z0.multiply(this.cipherText.getH().pow(response.getC0()));
        boolean challenge2Valid = left2.equals(right2);

        // g^s1 === y1 * G^c1
        ModInteger left3 = this.publicKey.getG().pow(response.getS1());
        ModInteger right3 = this.y1.multiply(this.cipherText.getG().pow(response.getC1()));
        boolean challenge3Valid = left3.equals(right3);

        // h^s1 === z1 * (H/g)^c1
        ModInteger left4 = this.publicKey.getH().pow(response.getS1());
        ModInteger right4 = this.z1.multiply(this.cipherText.getH().divide(this.publicKey.getG())).pow(this.c1);
        boolean challenge4Valid = left4.equals(right4);

        // c = c0 + c1
        boolean challenge5Valid = c.equals(response.getC0().add(response.getC1()));

        return challenge1Valid && challenge2Valid && challenge3Valid && challenge4Valid && challenge5Valid;
    }
}
