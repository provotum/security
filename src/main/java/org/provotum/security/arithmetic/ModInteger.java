package org.provotum.security.arithmetic;

import org.provotum.security.random.Context;

import java.math.BigInteger;

/**
 * A class abstracting modular arithmetic on integers.
 * If the modulo is set to 0, then the usual arithmetic operations are applied.
 * <p>
 * Some notes about modular arithmetic:
 * <ul>
 * <li><b>n modulus 0</b> for any n is zero.</li>
 * </ul>
 */
public class ModInteger implements Comparable<ModInteger> {

    /**
     * The ModInteger constant zero.
     */
    public static final ModInteger ZERO = new ModInteger("0");
    /**
     * The ModInteger constant one.
     */
    public static final ModInteger ONE = new ModInteger("1");
    /**
     * The ModInteger constant two.
     */
    public static final ModInteger TWO = new ModInteger("2");

    private static final Context CTX = new Context();

    private BigInteger value;
    private BigInteger modulus;

    /**
     * Creates an ModInteger with value and modulus of zero.
     */
    public ModInteger() {
        this.value = BigInteger.ZERO;
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Translates the integer representation of ModInteger into an
     * ModInteger. The integer is converted into a String and then
     * into a BigInteger.
     *
     * @param value int representation of ModInteger
     * @see BigInteger
     */
    public ModInteger(int value) {
        this.value = new BigInteger(value + "");
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Translates the String representation of an ModInteger in the specified
     * base into an ModInteger. The String representation consists of the same
     * format as BigInteger.
     *
     * @param value String representation of ModInteger
     * @param base  base to be used in interpreting <tt>value</tt>
     * @see BigInteger
     */
    public ModInteger(String value, int base) {
        this.value = new BigInteger(value, base);
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Translates the decimal BigInteger representation of an ModInteger with
     * the given modulus into an ModInteger. The String representation
     * consists of the same format as BigInteger.
     *
     * @param value   String representation of ModInteger
     * @param modulus the modulus
     * @see BigInteger
     */

    public ModInteger(BigInteger value, BigInteger modulus) {
        this.modulus = modulus;
        this.value = value.mod(modulus);
    }

    /**
     * Translates the String representation of an ModInteger in the specified
     * base and the given modulus into an ModInteger. The String
     * representation consists of the same format as BigInteger.
     *
     * @param value   String representation of ModInteger
     * @param modulus the modulus
     * @param base    base to be used in interpreting <tt>value</tt>
     * @see BigInteger
     */
    public ModInteger(String value, ModInteger modulus, int base) {
        this.value = new BigInteger(value, base).mod(modulus.value);
        this.modulus = modulus.value;
    }

    /**
     * Translates the integer representation of ModInteger with the given
     * modulus into an ModInteger. The integer is converted into a String
     * and then into a BigInteger.
     *
     * @param value   int representation of ModInteger
     * @param modulus the modulus
     * @see BigInteger
     */
    public ModInteger(int value, int modulus) {
        // Integer converted into string first and then to BigInteger
        BigInteger v = new BigInteger(value + "");
        BigInteger mv = new BigInteger(modulus + "");

        this.modulus = mv;
        this.value = v.mod(mv);
    }


    /**
     * Translates the decimal BigInteger representation of an ModInteger into
     * an ModInteger. The String representation consists of the same format as
     * BigInteger.
     *
     * @param value String representation of ModInteger
     * @see BigInteger
     */
    public ModInteger(BigInteger value) {
        this.value = value;
        this.modulus = BigInteger.ZERO;
    }

    /**
     * Translates the decimal String representation of an ModInteger into an
     * ModInteger.  The String representation consists of consists of the
     * same format as BigInteger.
     *
     * @param value decimal String representation of ModInteger
     * @see BigInteger
     */
    public ModInteger(String value) {
        this(value, 10);
    }

    /**
     * Translates the int representation of an ModInteger into an
     * ModInteger. The String representation consists of consists of the same
     * format as BigInteger.
     *
     * @param value   decimal String representation of BigInteger.
     * @param modulus the modulus
     * @see BigInteger
     */
    public ModInteger(int value, ModInteger modulus) {
        this(value + "", modulus, 10);
    }

    /**
     * Translates the decimal String representation of an ModInteger with the
     * specified modulus into an ModInteger. The String representation
     * consists of consists of the same format as BigInteger.
     *
     * @param value   decimal String representation of BigInteger
     * @param modulus the modulus
     * @see BigInteger
     */
    public ModInteger(String value, ModInteger modulus) {
        this(value, modulus, 10);
    }

    /**
     * Copies the the given ModInteger and modulus into this ModInteger.
     *
     * @param b       ModInteger to be copied
     * @param modulus the modulus
     * @see #toString()
     */
    public ModInteger(ModInteger b, ModInteger modulus) {
        this(b.value.toString(), modulus);
    }


    /**
     * Returns whether this ModInteger is value is divisible by the given
     * ModInteger.
     *
     * @param b value by which divisibility is to be computed.
     * @return <tt>true</tt> if divisible by the given ModInteger
     */
    public boolean isDivisible(ModInteger b) {
        BigInteger mod = value.remainder(b.value);
        return mod.equals(BigInteger.ZERO);
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
     * Returns a randomly generated ModInteger, uniformly distributed over
     * the range <tt>0</tt> to <tt>(n - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used. Note that this method always returns a
     * non-negative ModInteger.
     *
     * @param n the bound for the new ModInteger
     * @return the new ModInteger
     */
    public static ModInteger random(ModInteger n) {
        BigInteger t = n.value;

        while (t.compareTo(n.value) >= 0) {
            t = new BigInteger(n.value.bitLength(), CTX.getRandom());
        }


        ModInteger c = new ModInteger();

        c.modulus = n.value;
        c.value = t;

        return c;
    }

    /**
     * Returns a randomly generated int, uniformly distributed over
     * the range <tt>a</tt> to <tt>(b - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used.
     *
     * @param a the lower bound for the new int
     * @param b the upper bound for the new int
     * @return the new int
     */
    public static int random(int a, int b) {
        return CTX.getRandom().nextInt(b - a) + a;
    }

    /**
     * Returns a randomly generated ModInteger, uniformly distributed over
     * the range <tt>0</tt> to <tt>(n - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used. Note that this method always returns a
     * non-negative ModInteger.
     *
     * @param n the bound for the new ModInteger
     * @return the new ModInteger
     */
    public static ModInteger random(int n) {
        return random(new ModInteger(n));
    }

    /**
     * Returns a randomly generated ModInteger, uniformly distributed over
     * the range <tt>0</tt> to <tt>(n - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used. Note that this method always returns a
     * non-negative ModInteger.
     *
     * @param n the bound for the new ModInteger
     * @return the new ModInteger
     */
    public static ModInteger random(String n) {
        return random(new ModInteger(n));
    }

    /**
     * Returns a randomly generated ModInteger, uniformly distributed over
     * the range <tt>0</tt> to <tt>(n - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used. Note that this method always returns a
     * non-negative ModInteger.
     *
     * @param n the bound for the new ModInteger
     * @return the new ModInteger
     */
    public static ModInteger random(BigInteger n) {
        return random(new ModInteger(n));
    }

    /**
     * @return <tt>The additive inverse of value</tt>
     */
    public ModInteger negate() {

        ModInteger c = new ModInteger();
        c.modulus = this.modulus;

        if (! this.modulus.equals(BigInteger.ZERO)) {
            // we ensure that the value is not bigger than the modulus here
            this.value = this.value.mod(this.modulus);
        }

        c.value = ! modulus.equals(BigInteger.ZERO) ? modulus.subtract(value) : value.negate();

        return c;
    }

    /**
     * @param b value to be added to this ModInteger
     * @return Returns an ModInteger whose value is <tt>this.value + b.value</tt>
     */
    public ModInteger add(ModInteger b) {

        ModInteger c = new ModInteger();

        c.modulus = modulus;
        c.value = value.add(b.value);

        if (! modulus.equals(BigInteger.ZERO))
            c.value = c.value.mod(c.modulus);

        return c;
    }

    /**
     * @param b value to be subtracted from this ModInteger
     * @return Returns an ModInteger whose value is <tt>this.value - b.value</tt>
     */
    public ModInteger subtract(ModInteger b) {

        ModInteger c = new ModInteger();

        c.modulus = modulus;
        c.value = ! modulus.equals(BigInteger.ZERO) ? value.add((b.negate()).value) : value.subtract(b.value);

        return c;
    }

    /**
     * @param b value to be multiplied with this ModInteger
     * @return Returns an ModInteger whose value is <tt>this.value * b.value</tt>
     */
    public ModInteger multiply(ModInteger b) {
        ModInteger c = new ModInteger();

        c.modulus = modulus;
        c.value = value.multiply(b.value);

        if (! modulus.equals(BigInteger.ZERO))
            c.value = c.value.mod(c.modulus);

        return c;
    }

    /**
     * @param b value to be divided into this ModInteger
     * @return Returns an ModInteger whose value is <tt>this.value / b.value</tt>
     */

    public ModInteger divide(ModInteger b) {

        ModInteger c = new ModInteger();

        c.modulus = modulus;

        if (! modulus.equals(BigInteger.ZERO)) {

            BigInteger bInv = b.value.modInverse(modulus);

            c.value = value.multiply(bInv);
            c.value = c.value.mod(c.modulus);
        } else c.value = value.divide(b.value);

        return c;
    }

    /**
     * @param m value to be modded into this ModInteger
     * @return Returns an ModInteger whose value is <tt>this.value % m.value</tt>
     */
    public ModInteger mod(ModInteger m) {
        ModInteger c = new ModInteger();

        c.modulus = this.modulus;
        c.value = value.mod(m.value);

        return c;
    }

    /**
     * Returns an ModInteger whose value is
     * <tt>(this<sup>exponent</sup>)</tt>.
     *
     * @param exponent exponent to which this ModInteger is to be raised.
     * @return <tt>this<sup>exponent</sup></tt>
     */

    public ModInteger pow(ModInteger exponent) {
        ModInteger c = new ModInteger();

        c.modulus = modulus;

        c.value = ! modulus.equals(BigInteger.ZERO) ? value.modPow(exponent.value, c.modulus) : value.pow(exponent.value.intValue());

        return c;
    }

    /**
     * Returns an ModInteger whose value is
     * <tt>(this<sup>exponent</sup>)</tt>. Note that <tt>exponent</tt>
     * is an integer rather than an ModInteger.
     *
     * @param exponent exponent to which this ModInteger is to be raised.
     * @return <tt>this<sup>exponent</sup></tt>
     */
    public ModInteger pow(int exponent) {
        return pow(new ModInteger(exponent));
    }


    /**
     * Compares this ModInteger with the specified ModInteger. This method
     * is provided in preference to individual methods for each of the six
     * boolean comparison operators (&lt;, ==, &gt;, &gt;=, !=, &lt;=). The
     * suggested idiom for performing these comparisons is:
     * <tt>(x.compareTo(y)</tt> &lt;<i>op</i>&gt; <tt>0)</tt>,
     * where &lt;<i>op</i>&gt; is one of the six comparison operators.
     *
     * @param b ModInteger to which this ModInteger is to be compared.
     * @return -1, 0 or 1 as this BigInteger is numerically less than, equal to, or greater than <tt>b</tt>
     */
    public int compareTo(ModInteger b) {
        return value.compareTo(((ModInteger) b).value);
    }

    /**
     * Returns the hash code for this ModInteger.
     *
     * @return hash code for this ModInteger
     */
    public int hashCode() {
        return value.hashCode() | modulus.hashCode();
    }

    /**
     * Compares this ModInteger with the specified Object for equality.
     *
     * @param x Object to which this ModInteger is to be compared
     * @return <tt>true</tt> if and only if the specified Object is a
     * ModInteger whose value is numerically equal to this
     * ModInteger's value.
     */
    public boolean equals(Object x) {

        Boolean isThis = (x == this);
        Boolean isModIntegerAndEqual = (x instanceof ModInteger) && finalized().equals(((ModInteger) x).finalized());

        return isThis || isModIntegerAndEqual;
    }

    /**
     * Converts this ModInteger to a BigInteger.
     *
     * @return this ModInteger converted to a BigInteger
     */
    public BigInteger asBigInteger() {
        return value;
    }

    /**
     * Calculates the value modulus the modulus.
     *
     * @return The finalized value.
     */
    public BigInteger finalized() {
        if (0 < modulus.compareTo(BigInteger.ZERO)) {
            return value.mod(modulus);
        }

        return value;
    }

    /**
     * Returns the String representation of this ModInteger in the default
     * base of ten. This follows the same rules as BigInteger.
     *
     * @return String representation of this BigInteger in the given radix.
     * @see Integer#toString()
     * @see BigInteger#toString()
     */
    public String toString() {
        return this.finalized().toString();
    }

    /**
     * Returns the String representation of this ModInteger in the given
     * base. This follows the same rules as BigInteger.
     *
     * @param base base of the String representation
     * @return String representation of this BigInteger in the given radix.
     * @see Integer#toString()
     * @see BigInteger#toString(int)
     */
    public String asString(int base) {
        return value.toString(base);
    }

    public String asStringWithModulus() {
        return value.toString() + " modulus " + modulus.toString();
    }

    public int intValue() {
        return this.value.intValue();
    }
}
