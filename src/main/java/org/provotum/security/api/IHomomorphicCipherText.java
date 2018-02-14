package org.provotum.security.api;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;

import java.util.List;

/**
 * A cipher text providing a multiplication for homomorphic operation.
 */
public interface IHomomorphicCipherText<C> {

    /**
     * Perform a homomorphic operation on the current ciphertext.
     *
     * @param operand The operand.
     * @return The result of the applied operation.
     */
    C operate(C operand);

    /**
     * Verify that this cipher text is within a particular domain of values.
     *
     * @param publicKey The public key used during encryption of this cihpertext.
     * @param domain    An enumeration of all values the plaintext of this ciphertext may have.
     * @return True, if the encrypted plaintext is within the specified domain.
     */
    boolean verify(PublicKey publicKey, List<ModInteger> domain);
}
