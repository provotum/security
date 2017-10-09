package org.provotum.security.arithmetic;

import org.provotum.security.random.Context;

import java.math.BigInteger;

public class ModInteger implements Comparable<ModInteger> {

    private static final Context RANDOM_CONTEXT = new Context();

    public static final ModInteger ZERO = new ModInteger(new BigInteger("0", 10), BigInteger.ZERO);
    public static final ModInteger ONE = new ModInteger(new BigInteger("1", 10), BigInteger.ZERO);
    public static final ModInteger TWO = new ModInteger(new BigInteger("2", 10), BigInteger.ZERO);

    private BigInteger value;
    private BigInteger modulus;

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

    public ModInteger(int value) {
        this.value = new BigInteger(Integer.toString(value));
        this.modulus = BigInteger.ZERO;
    }

    public ModInteger(BigInteger value) {
        this.value = value;
        this.modulus = BigInteger.ZERO;
    }

    public ModInteger(BigInteger value, BigInteger modulus) {
        this.value = value;
        this.modulus = modulus;
    }

    public ModInteger(ModInteger value, ModInteger modulus) {
        this.value = new BigInteger(value.value.toString(), 10).mod(modulus.value);
        this.modulus = modulus.value;
    }

    public ModInteger add(ModInteger summand) {
        BigInteger sum = this.value.add(summand.value);

        if (!this.modulus.equals(BigInteger.ZERO)) {
            sum = sum.mod(this.modulus);
        }

        return new ModInteger(sum, this.modulus);
    }

    public ModInteger subtract(ModInteger subtrahend) {
        BigInteger difference;

        if (!this.modulus.equals(BigInteger.ZERO)) {
            difference = this.value.add(subtrahend.negate().value);
        } else {
            difference = this.value.subtract(subtrahend.value);
        }

        return new ModInteger(difference, this.modulus);
    }

    public ModInteger negate() {
        BigInteger negatedValue;

        if (!this.modulus.equals(BigInteger.ZERO)) {
            negatedValue = this.modulus.subtract(this.value);
        } else {
            negatedValue = this.value.negate();
        }

        return new ModInteger(negatedValue, this.modulus);
    }

    public ModInteger multiply(ModInteger multiplicand) {
        BigInteger product = this.value.multiply(multiplicand.value);

        if (!this.modulus.equals(BigInteger.ZERO)) {
            product = product.mod(this.modulus);
        }

        return new ModInteger(product, this.modulus);
    }

    public ModInteger divide(ModInteger divisor) {
        BigInteger quotient;

        if (!this.modulus.equals(BigInteger.ZERO)) {
            BigInteger divisorInverse = divisor.value.modInverse(this.modulus);
            quotient = this.value.multiply(divisorInverse);
            quotient = quotient.mod(this.modulus);
        } else {
            quotient = this.value.divide(divisor.value);
        }

        return new ModInteger(quotient, this.modulus);
    }

    public ModInteger pow(ModInteger exponent) {
        BigInteger exponentialValue;

        if (!this.modulus.equals(BigInteger.ZERO)) {
            exponentialValue = this.value.modPow(exponent.value, this.modulus);
        } else {
            exponentialValue = this.value.pow(exponent.value.intValue());
        }

        return new ModInteger(exponentialValue, this.modulus);
    }

    public ModInteger pow(int exponent) {
        return this.pow(new ModInteger(exponent));
    }

    public ModInteger modulo(ModInteger modulo) {
        return new ModInteger(
                this.value.mod(modulo.value),
                this.modulus
        );
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
