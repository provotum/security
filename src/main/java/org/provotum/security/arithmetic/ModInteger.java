package org.provotum.security.arithmetic;

import org.provotum.security.random.Context;

import java.math.BigInteger;

/**
 * A class abstracting modular arithmetic on integers.
 * If the modulo is set to 0, then the usual arithmetic operations are applied.
 * <p>
 * Some notes about modular arithmetic:
 * <ul>
 * <li><b>n mod 0</b> for any n is zero.</li>
 * </ul>
 */
public class ModInteger implements Comparable<ModInteger> {

    private static final Context RANDOM_CONTEXT = new Context();

    /**
     * An integer 0 with modulus 0.
     */
    public static final ModInteger ZERO = new ModInteger(new BigInteger("0", 10), BigInteger.ZERO);

    /**
     * An integer 1 with modulus 0.
     */
    public static final ModInteger ONE = new ModInteger(new BigInteger("1", 10), BigInteger.ZERO);

    /**
     * An integer 2 with modulus 0.
     */
    public static final ModInteger TWO = new ModInteger(new BigInteger("2", 10), BigInteger.ZERO);

    private BigInteger value;
    private BigInteger modulus;

    /**
     * Create an uniformly distributed random integer in the range of [0, bound - 1].
     * Note, that the modulus of the returned random integer is equal to the value of the given bound.
     *
     * @param bound The upper bound (exclusive) for generating random numbers.
     * @return The generated random integer.
     */
    public static ModInteger random(ModInteger bound) {
        BigInteger randomValue;

        do {
            randomValue = new BigInteger(bound.value.bitLength(), RANDOM_CONTEXT.getRandom());
        } while (randomValue.compareTo(bound.value) >= 0);

        // Note, that modulus is the given bound
        return new ModInteger(
                randomValue,
                bound.value
        );
    }

    /**
     * Create an integer of the given value with modulus of zero.
     *
     * @param value The value to use.
     */
    public ModInteger(int value) {
        this.value = new BigInteger(Integer.toString(value));
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Create an integer of the given value with the given modulus.
     * Note, that the given value is interpreted as a decimal number to which the
     * specified modulus is applied.
     *
     * @param value   The decimal value the integer should have (modulo the given modulus)
     * @param modulus The modulus the integer will have.
     */
    public ModInteger(int value, ModInteger modulus) {
        this.value = new BigInteger(Integer.toString(value, 10)).mod(modulus.value);
        this.modulus = modulus.value;
    }

    /**
     * Create an integer with the given value and a modulus of zero.
     *
     * @param value The value the integer should have.
     */
    public ModInteger(BigInteger value) {
        this.value = value;
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Create an integer of the given value and the given modulus.
     * <p>
     * <b>Note</b>, that if you use this constructor, then the given value
     * is not applied to the specified modulus.
     *
     * @param value   The value the integer will have. (without applying the specified modulus)
     * @param modulus The modulus the integer will have.
     */
    public ModInteger(BigInteger value, BigInteger modulus) {
        this.value = value;
        this.modulus = modulus;
    }

    /**
     * Create an integer with the given value and the specified modulus.
     *
     * @param value   The value the integer will have (modulo the given modulus)
     * @param modulus The modulus the integer will have.
     */
    public ModInteger(ModInteger value, ModInteger modulus) {
        this.value = new BigInteger(value.value.toString(), 10).mod(modulus.value);
        this.modulus = modulus.value;
    }

    /**
     * Add the given summand to the value of this instance.
     * Note, that the modulus of the given summand is ignored in all cases.
     *
     * @param summand The value to add.
     * @return The resulting sum.
     */
    public ModInteger add(ModInteger summand) {
        BigInteger sum = this.value.add(summand.value);

        if (! this.modulus.equals(BigInteger.ZERO)) {
            // if the modulus is specified, we just have to
            // take the sum modulo the modulus
            sum = sum.mod(this.modulus);
        }

        return new ModInteger(sum, this.modulus);
    }

    /**
     * Subtracts the given subtrahend from this instance.
     * The modulus in the given subtrahend is ignored in all cases.
     *
     * @param subtrahend The subtrahend to subtract.
     * @return The resulting difference.
     */
    public ModInteger subtract(ModInteger subtrahend) {
        BigInteger difference;

        if (! this.modulus.equals(BigInteger.ZERO)) {
            // subtraction in modular arithmetic
            // is the same as addition of the negated value.
            difference = this.value.add(subtrahend.negate().value);
        } else {
            difference = this.value.subtract(subtrahend.value);
        }

        return new ModInteger(difference, this.modulus);
    }

    /**
     * Negate this value. For usual arithmetic operations, this
     * integer will have the value of <code>- (this)</code>,
     * in case modular arithmetic is applied, the value will be the
     * opposite to the modulus.
     * As example consider the integer <code>1 mod 11</code>.
     * The negation then will be <code>10 mod 11</code>.
     *
     * @return The negation of this integer.
     */
    public ModInteger negate() {
        BigInteger negatedValue;

        if (! this.modulus.equals(BigInteger.ZERO)) {
            negatedValue = this.modulus.subtract(this.value);
        } else {
            negatedValue = this.value.negate();
        }

        return new ModInteger(negatedValue, this.modulus);
    }

    /**
     * Multiply this integer with the given multiplicand.
     *
     * @param multiplicand The multiplicand to use.
     * @return The applied multiplication.
     */
    public ModInteger multiply(ModInteger multiplicand) {
        BigInteger product = this.value.multiply(multiplicand.value);

        if (! this.modulus.equals(BigInteger.ZERO)) {
            product = product.mod(this.modulus);
        }

        return new ModInteger(product, this.modulus);
    }

    /**
     * Divide this integer with the specified divisor.
     *
     * @param divisor The divisor to apply.
     * @return The resulting division.
     */
    public ModInteger divide(ModInteger divisor) {
        BigInteger quotient;

        if (! this.modulus.equals(BigInteger.ZERO)) {
            BigInteger divisorInverse = divisor.value.modInverse(this.modulus);
            quotient = this.value.multiply(divisorInverse);
            quotient = quotient.mod(this.modulus);
        } else {
            quotient = this.value.divide(divisor.value);
        }

        return new ModInteger(quotient, this.modulus);
    }

    /**
     * Exponentiate this integer with the given exponent.
     *
     * @param exponent The exponent to use.
     * @return The resulting value.
     */
    public ModInteger pow(ModInteger exponent) {
        BigInteger exponentialValue;

        if (! this.modulus.equals(BigInteger.ZERO)) {
            exponentialValue = this.value.modPow(exponent.value, this.modulus);
        } else {
            exponentialValue = this.value.pow(exponent.value.intValue());
        }

        return new ModInteger(exponentialValue, this.modulus);
    }

    /**
     * Exponentiate this integer with the given exponent.
     *
     * @param exponent The exponent to use.
     * @return The resulting value.
     */
    public ModInteger pow(int exponent) {
        return this.pow(new ModInteger(exponent));
    }

    /**
     * Apply the given modulo to this value.
     *
     * @param modulo The value to apply.
     * @return The resulting value.
     */
    public ModInteger modulo(ModInteger modulo) {
        return new ModInteger(
                this.value.mod(modulo.value),
                this.modulus
        );
    }

    public BigInteger getValue() {
        return value;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public int compareTo(ModInteger b) {
        return this.value.compareTo(b.value);
    }

    public int hashCode() {
        return this.value.hashCode() | this.modulus.hashCode();
    }

    public boolean equals(Object b) {
        return this == b || b instanceof ModInteger && this.value.equals(((ModInteger) b).value);
    }

    public String toString(int base) {
        return this.value.toString(base);
    }
}
