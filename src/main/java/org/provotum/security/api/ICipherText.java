package org.provotum.security.api;

/**
 * A cipher text providing a multiplication for homomorphic operation.
 */
public interface ICipherText<C> {

    /**
     * Multiply the given cipher text's value with the
     * value of this instance.
     *
     * @param multiplicand The multiplicand.
     * @return The applied multiplication
     */
    C multiply(C multiplicand);
}
