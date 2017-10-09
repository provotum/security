package org.provotum.security.test.arithmetic;

import junit.framework.TestCase;
import org.provotum.security.AdderInteger;
import org.provotum.security.arithmetic.ModInteger;

import java.math.BigInteger;

public class ModIntegerTest extends TestCase {

    private ModInteger p;

    public void setUp() {
        BigInteger modulus = BigInteger.valueOf(11);
        BigInteger value = new BigInteger("23", 10).mod(modulus);

        this.p = new ModInteger(value, modulus);
        assertEquals(ModInteger.ONE, this.p);
    }

    public void testSubtraction() {
        ModInteger pMinusOne = this.p.subtract(ModInteger.ONE);
        assertEquals(ModInteger.ZERO, pMinusOne);
    }

    public void testSummation() {
        ModInteger pPlusOne = this.p.add(ModInteger.ONE);
        assertEquals(ModInteger.TWO, pPlusOne);

        ModInteger pPlusSix = this.p.add(new ModInteger(BigInteger.valueOf(6)));
        assertEquals(new ModInteger(BigInteger.valueOf(7)), pPlusSix);
    }

    public void testMultiplication() {
        ModInteger pTimesNine = this.p.multiply(new ModInteger(BigInteger.valueOf(9)));
        assertEquals(new ModInteger(BigInteger.valueOf(9)), pTimesNine);
    }

    public void testNegate() {
        ModInteger negativeP = this.p.negate();
        assertEquals(new ModInteger(BigInteger.valueOf(10)), negativeP);
    }

    public void testCombined() {
        ModInteger combined = this
                .p
                .subtract(ModInteger.ONE)
                .divide(ModInteger.TWO);

        assertEquals(ModInteger.ZERO, combined);
    }

}
