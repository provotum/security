package org.provotum.security.elgamal.additive;

import org.provotum.security.api.IHomomorphicCipherText;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.proof.noninteractive.MembershipProof;

import java.util.List;

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

    private ModInteger c1;
    private ModInteger c21;
    private ModInteger c22;
    private ModInteger r;
    private MembershipProof membershipProof;

    /**
     * Creates a new ciphertext of the form:
     * <pre>
     *     E = (G,H) = (g^r, h^r * g^m) = (c1, c21 * c22)
     * </pre>
     *
     * @param c1              g^r, with g being the generator of the cyclic group.
     * @param c21             h^r, with h being the public value h = g^x of the private key x.
     * @param c22             g^m, with g being the generator and m the message to encrypt.
     * @param r               The random value r used in the components above, in the range [0, q - 1]
     * @param membershipProof A membership proof ensuring that the plaintext value of this cipher is within a certain range.
     */
    public CipherText(ModInteger c1, ModInteger c21, ModInteger c22, ModInteger r, MembershipProof membershipProof) {
        this.c1 = c1;
        this.c21 = c21;
        this.c22 = c22;
        this.r = r;
        this.membershipProof = membershipProof;
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

        // g^r1 * g^r2
        this.c1 = this.c1.multiply(operand.c1);
        // h^r1 * h^r2
        this.c21 = this.c21.multiply(operand.c21);
        // g^m1 * g^m2
        this.c22 = this.c22.multiply(operand.c22);

        this.r = this.r.add(operand.getR());

        // TODO: recompute the proof

        return this;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(List<ModInteger> domain) {
        return this.membershipProof.verify(this, domain);
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
        return this.c1;
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
        return this.c21.multiply(this.c22);
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
}
