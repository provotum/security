package org.provotum.security.api;

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
}
