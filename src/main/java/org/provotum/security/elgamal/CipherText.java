package org.provotum.security.elgamal;

import org.provotum.security.arithmetic.ModInteger;

public class CipherText {

    private ModInteger p;
    private ModInteger g;
    private ModInteger h;
    private ModInteger r;

    public static CipherText encrypt(PublicKey publicKey, ModInteger message) {
        ModInteger random = ModInteger.random(publicKey.getQ());
        ModInteger bigG = publicKey.getG().pow(random);
        ModInteger bigH = publicKey.getY().pow(random).multiply(message);

        // G = g^r
        // H = y^r

        return new CipherText(publicKey.getP(), bigG, bigH, random);
    }

    public static CipherText encryptPolynomial(PublicKey publicKey, ModInteger message) {
        ModInteger random = ModInteger.random(publicKey.getQ());
        ModInteger bigG = publicKey.getG().pow(random);
        ModInteger messagePlusOne = new ModInteger(message.add(ModInteger.ONE), publicKey.getP());
        ModInteger bigH = publicKey.getY().pow(random).multiply(messagePlusOne.pow(ModInteger.TWO));

        return new CipherText(publicKey.getP(), bigG, bigH);
    }

    /**
     * @param p The prime
     * @param g The generator
     * @param h The public value
     */
    public CipherText(ModInteger p, ModInteger g, ModInteger h) {
        this.p = p;
        this.g = g;
        this.h = h;
        this.r = ModInteger.ZERO;
    }

    private CipherText(ModInteger p, ModInteger g, ModInteger h, ModInteger r) {
        this.p = p;
        this.g = g;
        this.h = h;
        this.r = r;
    }

    public CipherText multiply(CipherText cipherText) {
        ModInteger g = this.g.multiply(cipherText.g);
        ModInteger h = this.h.multiply(cipherText.h);
        ModInteger r = this.r.add(cipherText.r);

        return new CipherText(this.p, g, h, r);
    }

    public ModInteger getG() {
        return g;
    }

    public ModInteger getH() {
        return h;
    }
}
