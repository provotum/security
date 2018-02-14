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

    private BigInteger val;
    private BigInteger mod;
    private static final Context CTX = new Context();


    /**
     * Creates an ModInteger with value and modulus of zero.
     */
    public ModInteger() {
        this.val = BigInteger.ZERO;
        this.mod = BigInteger.ZERO;
    }

    /**
     * Copies the the given ModInteger into this ModInteger.
     *
     * @param b     ModInteger to be copied
     */
    public ModInteger(ModInteger b) {
        this.val = b.val;
        this.mod = b.mod;
    }

    /**
     * Translates the integer representation of ModInteger into an
     * ModInteger. The integer is converted into a String and then
     * into a BigInteger.
     *
     * @param val      int representation of ModInteger
     * @see            BigInteger
     */
    public ModInteger(int val) {
        this.val = new BigInteger(val + "");
        this.mod = BigInteger.ZERO;
    }

    /**
     * Translates the String representation of an ModInteger in the specified
     * base into an ModInteger. The String representation consists of the same
     * format as BigInteger.
     *
     * @param val      String representation of ModInteger
     * @param base     base to be used in interpreting <tt>val</tt>
     * @see            BigInteger
     */
    public ModInteger(String val, int base) {
        this.val = new BigInteger(val, base);
        this.mod = BigInteger.ZERO;
    }

    /**
     * Translates the decimal BigInteger representation of an ModInteger with
     * the given modulus into an ModInteger. The String representation
     * consists of the same format as BigInteger.
     *
     * @param val      String representation of ModInteger
     * @param mod      the modulus
     * @see            BigInteger
     */

    public ModInteger(BigInteger val, BigInteger mod) {
        this.mod = mod;
        this.val = val.mod(mod);
    }

    /**
     * Translates the String representation of an ModInteger in the specified
     * base and the given modulus into an ModInteger. The String
     * representation consists of the same format as BigInteger.
     *
     * @param val      String representation of ModInteger
     * @param mod      the modulus
     * @param base     base to be used in interpreting <tt>val</tt>
     * @see            BigInteger
     */
    public ModInteger(String val, ModInteger mod, int base) {
        this.val = new BigInteger(val, base).mod(mod.val);
        this.mod = mod.val;
    }

    /**
     * Translates the integer representation of ModInteger with the given
     * modulus into an ModInteger. The integer is converted into a String
     * and then into a BigInteger.
     *
     * @param val      int representation of ModInteger
     * @param mod      the modulus
     * @see            BigInteger
     */
    public ModInteger(int val, int mod) {

        /* Integer converted into string first and then to BigInteger*/
        BigInteger v = new BigInteger(val + "");
        BigInteger mv = new BigInteger(mod + "");

        this.mod = mv;
        this.val = v.mod(mv);
    }


    /**
     * Translates the decimal BigInteger representation of an ModInteger into
     * an ModInteger. The String representation consists of the same format as
     * BigInteger.
     *
     * @param val       String representation of ModInteger
     * @see             BigInteger
     */
    public ModInteger(BigInteger val) {
        this.val = val;
        this.mod = BigInteger.ZERO;
    }

    /**
     * Translates the decimal String representation of an ModInteger into an
     * ModInteger.  The String representation consists of consists of the
     * same format as BigInteger.
     *
     * @param val       decimal String representation of ModInteger
     * @see             BigInteger
     */
    public ModInteger(String val) {
        this(val, 10);
    }

    /**
     * Translates the int representation of an ModInteger into an
     * ModInteger. The String representation consists of consists of the same
     * format as BigInteger.
     *
     * @param val       decimal String representation of BigInteger.
     * @param mod       the modulus
     * @see             BigInteger
     */
    public ModInteger(int val, ModInteger mod) {
        this(val + "", mod, 10);
    }

    /**
     * Translates the decimal String representation of an ModInteger with the
     * specified modulus into an ModInteger. The String representation
     * consists of consists of the same format as BigInteger.
     *
     * @param val       decimal String representation of BigInteger
     * @param mod       the modulus
     * @see             BigInteger
     */
    public ModInteger(String val, ModInteger mod) {
        this(val, mod, 10);
    }

    /**
     * Translates the decimal String representation of an ModInteger with the
     * specified modulus into an ModInteger. The String representation
     * consists of consists of the same format as BigInteger.
     *
     * @param val       decimal String representation of BigInteger
     * @param mod       the modulus
     */
    public ModInteger(String val, String mod) {
        this(val, new ModInteger(mod));
    }

    /**
     * Copies the the given ModInteger and modulus into this ModInteger.
     *
     * @param b         ModInteger to be copied
     * @param mod       the modulus
     * @see             #toString()
     */
    public ModInteger(ModInteger b, ModInteger mod) {
        this(b.val.toString(), mod);
    }


    /**
     * Returns whether this ModInteger is value is divisible by the given
     * ModInteger.
     *
     * @param  b        value by which divisibility is to be computed.
     * @return          <tt>true</tt> if divisible by the given ModInteger
     */
    public boolean isDivisible(ModInteger b) {
        BigInteger mod = val.remainder(b.val);
        return mod.equals(BigInteger.ZERO);
    }

    /**
     * Gets the value of this ModInteger.
     *
     * @return          the value
     */
    public ModInteger getValue() {
        return new ModInteger(val);
    }

    /**
     * Gets the modulus of this ModInteger.
     *
     * @return          the modulus
     */
    public ModInteger getModulus() {
        return new ModInteger(mod);
    }

    /**
     * Returns a randomly generated ModInteger, uniformly distributed over
     * the range <tt>0</tt> to <tt>(n - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used. Note that this method always returns a
     * non-negative ModInteger.
     *
     * @param  n        the bound for the new ModInteger
     * @return          the new ModInteger
     */
    public static ModInteger random(ModInteger n) {

        BigInteger t = n.val;

        while (t.compareTo(n.val) >= 0)
            t = new BigInteger (n.val.bitLength(), CTX.getRandom());


        ModInteger c = new ModInteger();

        c.mod = n.val;
        c.val = t;

        return c;
    }

    /**
     * Returns a randomly generated int, uniformly distributed over
     * the range <tt>a</tt> to <tt>(b - 1)</tt>, inclusive.
     * The uniformity of the distribution should be uniform, as a secure source
     * of randomness is used.
     *
     * @param  a        the lower bound for the new int
     * @param  b        the upper bound for the new int
     * @return          the new int
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
     * @param  n        the bound for the new ModInteger
     * @return          the new ModInteger
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
     * @param  n        the bound for the new ModInteger
     * @return          the new ModInteger
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
     * @param  n        the bound for the new ModInteger
     * @return          the new ModInteger
     */
    public static ModInteger random(BigInteger n) {
        return random(new ModInteger(n));
    }

    /**
     * Returns a positive ModInteger that is probably a safe prime, with
     * the specified bitLength. The probability that an ModInteger returned
     * by this method is composite does not exceed 2<sup>-100</sup>.
     *
     * @param  bitLength    bitLength of the returned BigInteger.
     * @return              an ModInteger of <tt>bitLength</tt> bits that is probably a safe prime
     * @see                 BigInteger#bitLength()
     */
    public static ModInteger safePrime(int bitLength) {

        final BigInteger two = new BigInteger("2");
        BigInteger p;
        BigInteger q;

        do {
            p = BigInteger.probablePrime(bitLength, CTX.getRandom());
            q = p.subtract(BigInteger.ONE).divide(two);
        } while (!q.isProbablePrime(100));

        return new ModInteger(p);
    }

    /**
     * @return          <tt>The additive inverse of val</tt>
     */
    public ModInteger negate() {

        ModInteger c = new ModInteger();

        if (! this.mod.equals(BigInteger.ZERO)) {
            // we ensure that the value is not bigger than the modulus here
            this.val = this.val.mod(this.mod);
        }

        c.val = !mod.equals(BigInteger.ZERO) ? mod.subtract(val) : val.negate();

        return c;
    }

    /**
     * @see BigInteger#add(BigInteger)
     *
     * @param  b        value to be added to this ModInteger
     * @return          Returns an ModInteger whose value is <tt>this.val + b.val</tt>
     */
    public ModInteger add(ModInteger b) {

        ModInteger c = new ModInteger();

        c.mod = mod;
        c.val = val.add(b.val);

        if (!mod.equals(BigInteger.ZERO))
            c.val = c.val.mod(c.mod);

        return c;
    }

    /**
     * @see BigInteger#subtract(BigInteger)
     *
     * @param  b        value to be subtracted from this ModInteger
     * @return          Returns an ModInteger whose value is <tt>this.val - b.val</tt>
     */
    public ModInteger subtract(ModInteger b) {

        ModInteger c = new ModInteger();

        c.mod = mod;
        c.val = !mod.equals(BigInteger.ZERO) ? val.add((b.negate()).val) : val.subtract(b.val);

        return c;
    }

    /**
     * @see BigInteger#multiply(BigInteger)
     *
     * @param  b        value to be multiplied with this ModInteger
     * @return          Returns an ModInteger whose value is <tt>this.val * b.val</tt>
     */
    public ModInteger multiply(ModInteger b) {
        ModInteger c = new ModInteger();

        c.mod = mod;
        c.val = val.multiply(b.val);

        if (!mod.equals(BigInteger.ZERO))
            c.val = c.val.mod(c.mod);

        return c;
    }

    /**
     * @see BigInteger#divide(BigInteger)
     *
     * @param  b        value to be divided into this ModInteger
     * @return          Returns an ModInteger whose value is <tt>this.val / b.val</tt>
     */

    public ModInteger divide(ModInteger b) {

        ModInteger c = new ModInteger();

        c.mod = mod;

        if (!mod.equals(BigInteger.ZERO)) {

            BigInteger bInv = b.val.modInverse(mod);

            c.val = val.multiply(bInv);
            c.val = c.val.mod(c.mod);
        }
        else  c.val = val.divide(b.val);

        return c;
    }

    /**
     * @see BigInteger#mod(BigInteger)
     *
     * @param  m        value to be modded into this ModInteger
     * @return          Returns an ModInteger whose value is <tt>this.val % m.val</tt>
     */
    public ModInteger mod(ModInteger m) {
        ModInteger c = new ModInteger();

        c.mod = this.mod;
        c.val = val.mod(m.val);

        return c;
    }

    /**
     * Returns an ModInteger whose value is
     * <tt>(this<sup>exponent</sup>)</tt>.
     *
     * @param  exponent     exponent to which this ModInteger is to be raised.
     * @return              <tt>this<sup>exponent</sup></tt>
     */

    public ModInteger pow(ModInteger exponent) {
        ModInteger c = new ModInteger();

        c.mod = mod;

        c.val = !mod.equals(BigInteger.ZERO) ? val.modPow(exponent.val, c.mod) : val.pow(exponent.val.intValue());

        return c;
    }

    /**
     * Returns an ModInteger whose value is
     * <tt>(this<sup>exponent</sup>)</tt>. Note that <tt>exponent</tt>
     * is an integer rather than an ModInteger.
     *
     * @param  exponent     exponent to which this ModInteger is to be raised.
     * @return              <tt>this<sup>exponent</sup></tt>
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
     * @param  b        ModInteger to which this ModInteger is to be compared.
     * @return          -1, 0 or 1 as this BigInteger is numerically less than, equal to, or greater than <tt>b</tt>
     */
    public int compareTo(ModInteger b) {
        return val.compareTo(((ModInteger) b).val);
    }

    /**
     * Returns the hash code for this ModInteger.
     *
     * @return          hash code for this ModInteger
     */
    public int hashCode() {
        return val.hashCode() | mod.hashCode();
    }

    /**
     * Compares this ModInteger with the specified Object for equality.
     *
     * @param  x        Object to which this ModInteger is to be compared
     * @return          <tt>true</tt> if and only if the specified Object is a
     *                  ModInteger whose value is numerically equal to this
     *                  ModInteger's value.
     */
    public boolean equals(Object x) {

        Boolean isThis = (x==this);
        Boolean isModIntegerAndEqual = (x instanceof ModInteger) && val.equals(((ModInteger) x).val);

        return isThis || isModIntegerAndEqual;
    }

    /**
     * Converts this ModInteger to an <tt>int</tt>. This
     * conversion is equivalent to BigInteger.
     *
     * @return           this ModInteger converted to an <tt>int</tt>
     * @see              BigInteger#intValue()
     */
    public int intValue() {
        return val.intValue();
    }

    /**
     * Converts this ModInteger to a BigInteger.
     *
     * @return           this ModInteger converted to a BigInteger
     * @see              BigInteger
     */
    public BigInteger bigintValue() {
        return val;
    }

    /**
     * Returns the String representation of this ModInteger in the default
     * base of ten. This follows the same rules as BigInteger.
     *
     * @return          String representation of this BigInteger in the given radix.
     * @see             Integer#toString()
     * @see             BigInteger#toString()
     */
    public String toString() {
        return val.toString();
    }

    /**
     * Returns the String representation of this ModInteger in the given
     * base. This follows the same rules as BigInteger.
     *
     * @param  base     base of the String representation
     * @return          String representation of this BigInteger in the given radix.
     * @see             Integer#toString()
     * @see             BigInteger#toString(int)
     */
    public String toString(int base) {
        return val.toString(base);
    }

    public String toStringWithModulus() {
        return val.toString() + " mod " + mod.toString();
    }
}
