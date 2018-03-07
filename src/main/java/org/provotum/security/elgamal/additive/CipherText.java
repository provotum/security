package org.provotum.security.elgamal.additive;

import org.provotum.security.api.IHomomorphicCipherText;
import org.provotum.security.arithmetic.ModInteger;

/**
 * An additive homomorphic ElGamal ciphertext.
 * The homomorphic operation is a multiplication of the encrypted values
 * resulting in an addition of the plaintext values.
 * <p>
 * <pre>
 *   E(m) = (g^r, h^r * g^m), with
 * </pre>
 * <p>
 * with:
 * <ul>
 * <li>g = generator</li>
 * <li>m = message</li>
 * <li>h = g^x i.e. the public key whereas x = private key</li>
 * <li>r = [0, q-1]</li>
 * </ul>
 * <pre>
 * E(m1) * E(m2) = (g^(r1+r2), h^(r1+r2) * g^(m1+m2))
 *               = E(m1 + m2)
 * </pre>
 */
public class CipherText implements IHomomorphicCipherText<CipherText> {

    private final ModInteger r;
    private final ModInteger bigH;
    private final ModInteger bigG;

    /**
     * Creates a new ciphertext of the form:
     * <pre>
     *     E = (G,H) = (g^r, h^r * g^m) = (c1, c21 * c22)
     * </pre>
     *
     * @param bigG g^r, with g being the generator of the cyclic group.
     * @param bigH h^r, with h being the public value h = g^x of the private key x <tt>times</tt> g^m, with g being the generator and m the message to encrypt.
     * @param r    The random value r used in the components above, in the range [0, q - 1]
     */
    public CipherText(ModInteger bigG, ModInteger bigH, ModInteger r) {
        this.bigG = bigG;
        this.bigH = bigH;
        this.r = r;
    }

    /**
     * {@inheritDoc}
     * <p>
     * Multiply the given cipher text with this instance: In terms
     * of arithmetic, adds the given cipher text's plaintext value to this instance's value.
     * <p>
     * <pre>
     *   E(m) = (g^r, h^r * g^m), with
     * </pre>
     * <p>
     * with:
     * <ul>
     * <li>g = generator</li>
     * <li>m = message</li>
     * <li>h = g^x i.e. the public key whereas x = private key</li>
     * <li>r = [0, q-1]</li>
     * </ul>
     * <pre>
     * E(m1) * E(m2) = (g^(r1+r2), h^(r1+r2) * g^(m1+m2))
     *               = E(m1 + m2)
     * </pre>
     *
     * @param operand The cipher text to add using multiplication.
     * @return The resulting cipher text
     */
    public CipherText operate(CipherText operand) {
        // E(m) = (G, H) = (c1, c21 * c22) = (g^r, h^r * g^m)
        return new CipherText(
            this.bigG.multiply(operand.bigG),
            this.bigH.multiply(operand.bigH),
            this.r.add(operand.r)
        );
    }

    /**
     * Returns the first component of the encrypted message:
     * <pre>
     *      E = (G,H) = (g^r, h^r * g^m) = (c1, c21 * c22)
     * </pre>
     *
     * @return The first component of the encrypted message.
     */
    public ModInteger getG() {
        return this.bigG;
    }

    /**
     * Returns the second component of the encrypted message:
     * <pre>
     *      E = (G,H) = (g^r, h^r * g^m) = (c1, c21 * c22)
     * </pre>
     *
     * @return The first component of the encrypted message.
     */
    public ModInteger getH() {
        return this.bigH;
    }

    /**
     * Returns the random number r used in the encrypted message:
     * <pre>
     *      E = (G,H) = (g^r, h^r * g^m) = (c1, c21 * c22)
     * </pre>
     *
     * @return The first component of the encrypted message.
     */
    public ModInteger getR() {
        return this.r;
    }

    @Override
    public int hashCode() {
        return this.bigG.finalized().hashCode() | this.bigH.finalized().hashCode() | this.r.finalized().hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return (this == o) || (o instanceof CipherText) &&
            this.bigG.equals(((CipherText) o).bigG) &&
            this.bigH.equals(((CipherText) o).bigH) &&
            this.r.equals(((CipherText) o).r);
    }

    @Override
    public CipherText clone() {
        return new CipherText(this.bigG.clone(), this.bigH.clone(), this.r.clone());
    }

}
