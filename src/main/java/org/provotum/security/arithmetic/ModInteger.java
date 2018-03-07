package org.provotum.security.arithmetic;

import org.provotum.security.random.Context;

import java.math.BigInteger;

/**
 * This class provides an abstraction
 * for calculations in modular arithmetics.
 * <p>
 * Each ModInteger is represented by a value mod a modulus.
 */
public class ModInteger implements Comparable<ModInteger> {

    private static final Context RANDOM_CONTEXT = new Context();

    public static final ModInteger ZERO = new ModInteger("0");
    public static final ModInteger ONE = new ModInteger("1");
    public static final ModInteger TWO = new ModInteger("2");

    private final BigInteger value;
    private final BigInteger modulus;

    /**
     * Create a ModInteger of the form:
     * <pre>value mod 0</pre>
     *
     * @param value The value of the ModInteger.
     */
    public ModInteger(BigInteger value) {
        this.value = value;
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Create a ModInteger with the given value.
     * <pre>value_10 mod 0</pre>
     *
     * @param value The value in decimal form.
     */
    public ModInteger(String value) {
        this.value = new BigInteger(value);
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Create a ModInteger with the given value and modulus.
     *
     * @param value   The value.
     * @param modulus The modulus.
     */
    public ModInteger(String value, String modulus) {
        this.value = finalize(new BigInteger(value), new BigInteger(modulus));
        this.modulus = new BigInteger(modulus);
    }

    /**
     * Create a ModInteger with the given value and the given modulus:
     * <pre>value mod modulus</pre>
     *
     * @param value   The value of the ModInteger.
     * @param modulus The modulus of the value.
     */

    public ModInteger(BigInteger value, BigInteger modulus) {
        this.value = finalize(value, modulus);
        this.modulus = modulus;
    }

    /**
     * Create a new ModInteger with the given value and modulus whereas the value is relative to the specified base.
     * <pre>value_base mod modulus</pre>
     *
     * @param value   The value of the ModInteger.
     * @param modulus The modulus of the value.
     * @param base    The base of the value.
     */
    public ModInteger(String value, ModInteger modulus, int base) {
        this.value = finalize(new BigInteger(value, base), modulus.value);
        this.modulus = modulus.value;
    }

    /**
     * Create a ModInteger with the given value and modulus.
     * <pre>value_10 mod modulus</pre>
     *
     * @param value   decimal String representation of BigInteger
     * @param modulus the modulus
     */
    public ModInteger(String value, ModInteger modulus) {
        this(value, modulus, 10);
    }

    /**
     * Create a ModInteger with the given value and modulus.
     * <pre>value mod modulus</pre>
     *
     * @param value   The value.
     * @param modulus The modulus.
     */
    public ModInteger(ModInteger value, ModInteger modulus) {
        this(value.value.toString(), modulus);
    }


    /**
     * Gets the value of this ModInteger.
     *
     * @return the value
     */
    public ModInteger getValue() {
        return new ModInteger(value);
    }

    /**
     * Gets the modulus of this ModInteger.
     *
     * @return the modulus
     */
    public ModInteger getModulus() {
        return new ModInteger(modulus);
    }

    /**
     * Creates a non-negative ModInteger in the range of [0, bound).
     *
     * @param bound The upper bound of the ModInteger to create (exclusive).
     * @return A uniformly distributed random integer.
     * @throws IllegalArgumentException If the given bound is smaller than 1.
     */
    public static ModInteger random(ModInteger bound) throws IllegalArgumentException {
        BigInteger rnd = bound.value;

        // check that the given bound is greater than 1.
        // Otherwise we will run into a loop.
        if (rnd.compareTo(BigInteger.ONE) <= 0) {
            throw new IllegalArgumentException("The given bound should be greater than 1. (Otherwise the only value returned will be 0).");
        }

        while (rnd.compareTo(bound.value) >= 0) {
            rnd = new BigInteger(bound.value.bitLength(), RANDOM_CONTEXT.getRandom());
        }

        return new ModInteger(
            rnd,
            bound.value
        );
    }

    /**
     * Negates this ModInteger in terms of modular arithmetic if its modulus is not equal to zero.
     * Otherwise in terms of standard arithmetics (- ModInteger).
     *
     * @return The inverse of this ModInteger.
     */
    public ModInteger negate() {
        BigInteger finalizedValue = this.finalized();

        BigInteger val;
        if (modulus.equals(BigInteger.ZERO)) {
            val = finalizedValue.negate();
        } else {
            val = modulus.subtract(finalizedValue);
        }

        return new ModInteger(val, this.modulus);
    }

    /**
     * Add the given value to this ModInteger.
     * Uses the modulus of this ModInteger.
     *
     * @param summand The value to add.
     * @return The sum of this ModInteger and the specified summand.
     */
    public ModInteger add(ModInteger summand) {
        return new ModInteger(
            finalize(this.value.add(summand.value), this.modulus),
            this.modulus
        );
    }

    /**
     * Subtract the given subtrahend of this ModInteger.
     *
     * @param subtrahend The value to subtract.
     * @return The difference of this ModInteger and the given subtrahend.
     */
    public ModInteger subtract(ModInteger subtrahend) {
        BigInteger val;

        if (modulus.equals(BigInteger.ZERO)) {
            val = value.subtract(subtrahend.value);
        } else {
            val = value.add((subtrahend.negate()).value);
        }

        return new ModInteger(
            finalize(val, this.modulus),
            this.modulus
        );
    }

    /**
     * Multiply the given multiplicand with this ModInteger.
     *
     * @param multiplier The multiplier.
     * @return The product of this ModInteger and the specified multiplier.
     */
    public ModInteger multiply(ModInteger multiplier) {
        return new ModInteger(
            finalize(value.multiply(multiplier.value), this.modulus),
            this.modulus
        );
    }

    /**
     * Divide this ModInteger with the specified divisor.
     *
     * @param divisor The divisor.
     * @return The resulting quotient.
     */

    public ModInteger divide(ModInteger divisor) {
        BigInteger val;
        if (! this.modulus.equals(BigInteger.ZERO)) {
            BigInteger bInv = divisor.value.modInverse(modulus);

            val = value.multiply(bInv);
            val = val.mod(this.modulus);
        } else {
            val = value.divide(divisor.value);
        }

        return new ModInteger(val, this.modulus);
    }

    /**
     * Applies the given modulus to this ModInteger.
     * <pre>this mod modulus</pre>
     *
     * @param modulus The modulus to apply.
     * @return The remainder of the division by the given modulus.
     */
    public ModInteger mod(ModInteger modulus) {
        return new ModInteger(
            finalize(this.value, modulus.modulus),
            this.modulus
        );
    }

    /**
     * Exponentiate this ModInteger to the power of the given exponent.
     * Note, that the modulus of the given exponent is ignored.
     *
     * @param exponent The exponent.
     * @return The resulting exponentiation.
     */
    public ModInteger pow(ModInteger exponent) {
        BigInteger val;
        if (this.modulus.equals(BigInteger.ZERO)) {
            val = this.value.pow(exponent.value.intValue());
        } else {
            val = this.value.modPow(exponent.value, this.modulus);
        }

        return new ModInteger(
            finalize(val, this.modulus),
            this.modulus
        );
    }

    /**
     * Exponentiate this ModInteger to the power of the given exponent.
     *
     * @param exponent The exponent.
     * @return The resulting exponentiation.
     */
    public ModInteger pow(int exponent) {
        return pow(new ModInteger(Integer.toString(exponent)));
    }

    /**
     * @return A BigInteger representation of this ModInteger.
     */
    public BigInteger asBigInteger() {
        return this.finalized();
    }

    /**
     * @return A integer representation of this ModInteger.
     */
    public int intValue() {
        return this.finalized().intValue();
    }

    /**
     * Calculates the value modulo the modulus.
     * <pre>value mod modulus</pre>
     *
     * @return The resulting value.
     */
    public BigInteger finalized() {
        return finalize(this.value, this.modulus);
    }

    /**
     * Calculates the value modulo the modulus, if the given modulus is not equal to zero.
     *
     * @param value   The value.
     * @param modulus The modulus.
     * @return The value mod modulus.
     */
    private static BigInteger finalize(BigInteger value, BigInteger modulus) {
        if (0 < modulus.compareTo(BigInteger.ZERO)) {
            return value.mod(modulus);
        }

        return value;
    }

    @Override
    public int compareTo(ModInteger o) {
        return this.finalized().compareTo(o.value);
    }

    @Override
    public int hashCode() {
        return this.finalized().hashCode() | modulus.hashCode();
    }

    @Override
    public boolean equals(Object o) {
        return (this == o) || (o instanceof ModInteger) && this.finalized().equals(((ModInteger) o).finalized());
    }

    @Override
    public ModInteger clone() {
        return new ModInteger(new BigInteger(this.value.toString()), new BigInteger(this.modulus.toString()));
    }

    @Override
    public String toString() {
        return this.finalized().toString();
    }
}
