package org.provotum.security.api;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.proof.noninteractive.MembershipProof;

public interface IMembershipProofFactory<P extends IMembershipProof> {

    /**
     * Create a proof out of the given values.
     *
     * @param p       The prime modulus.
     * @param q       The value q, in relation to p in form of q = (p-1)/2.
     * @param g       The generator.
     * @param h       The public value of the private key: h = g^x
     * @param message The message to create the proof for.
     * @param bigG    The first component of the ElGamal Encryption E(m) = (G,H) = (g^r, h^r * g^m)
     * @param bigH    The second component of the ElGamal Encryption E(m) = (G,H) = (g^r, h^r * g^m)
     * @param random  The random number used in the calculations above.
     * @return The created membership proof.
     */
    P createProof(ModInteger p, ModInteger q, ModInteger g, ModInteger h, ModInteger message, ModInteger bigG, ModInteger bigH, ModInteger random);

    /**
     * Reconstruct the proof from its string representation.
     *
     * @param s The string representation of the proof.
     * @return The proof.
     * @see MembershipProof#toString()
     */
    P fromString(String s);
}
