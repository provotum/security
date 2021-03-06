package org.provotum.security.elgamal.additive;

import org.provotum.security.api.IHomomorphicEncryption;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PrivateKey;
import org.provotum.security.elgamal.PublicKey;

/**
 * This implementation provides additive homomorphic encryption using ElGamal.
 * <p>
 * The notation used within this class is as follows:
 * g = generator
 * m = message to encrypt
 * x = private key
 * h = g^x, i.e. the public key
 * <p>
 * An encrypted message is denoted by E(m) = (g^r, g^m * h^r)
 * <p>
 * Additive homomorphic encryption works then as follows:
 * <pre>
 * E(m1) * E(m2) = (c11, c21) * (c21, c22)
 *               = (g^r1, g^m1 * h^r1) * (g^r2, g^m2 * h^r2)
 *               = ( g^(r1+r2), g^(m1+m2) * h^(r1+r2) )
 *               = E(m1 + m2)
 * </pre>
 */
public class Encryption implements IHomomorphicEncryption<CipherText> {

    /**
     * {@inheritDoc}
     */
    @Override
    public CipherText encrypt(PublicKey publicKey, ModInteger message) {
        ModInteger random = ModInteger.random(publicKey.getQ());

        // We split the second part, i.e. c21 into two
        // for easier calculation of the multiplication.
        // So this becomes:
        // E(m) = (c1, c211 * c212) = (g^r, h^r * g^m)

        ModInteger c1 = publicKey.getG().pow(random);
        ModInteger c21 = publicKey.getH().pow(random);
        ModInteger c22 = publicKey.getG().pow(message);

        return new CipherText(c1, c21.multiply(c22), random);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public ModInteger decrypt(PrivateKey privateKey, CipherText cipherText) {
        // g^m = (h^r * g^m) / (g^r)^x
        ModInteger gToM = cipherText.getH().divide(cipherText.getG().pow(privateKey.getX()));

        // Decrypting is solving the discrete log:
        // We compare for each possible value of m whether it is equal to g^m.
        // Note, that this operation is linear in the message space.

        int i = 0;
        while (true) {
            ModInteger target = new ModInteger(privateKey.getG(), gToM.getModulus()).pow(i);

            if (target.equals(gToM)) {
                return new ModInteger(Integer.toString(i));
            }

            i++;
        }
    }
}
