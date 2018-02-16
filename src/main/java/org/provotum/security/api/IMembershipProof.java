package org.provotum.security.api;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;

import java.util.List;

public interface IMembershipProof<C extends IHomomorphicCipherText> {

    /**
     * Verify that the given ciphertext is with the specified list of domain values.
     *
     * @param cipherText The ciphertext to verify its range.
     * @param domain     A list of plaintext values the encrypted plaintext may have.
     * @return True, if the encrypted ciphertext represents a value within the given domain, false otherwise.
     */
    boolean verify(PublicKey publicKey, C cipherText, List<ModInteger> domain);
}
