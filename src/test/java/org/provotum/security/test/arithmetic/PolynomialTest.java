package org.provotum.security.test.arithmetic;

import junit.framework.TestCase;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.arithmetic.Polynomial;

import java.math.BigInteger;

public class PolynomialTest extends TestCase {

    public void testGetters() {
        Polynomial polynomial = new Polynomial(
                new ModInteger(BigInteger.valueOf(123)),
                new ModInteger(BigInteger.valueOf(61)),
                new ModInteger(BigInteger.valueOf(0)),
                2
        );

        assertEquals(3, polynomial.getCoefficients().size());
        assertTrue(new ModInteger(BigInteger.valueOf(28)).equals(polynomial.getCoefficients().get(1)));
        assertEquals(2, polynomial.getDegree());
    }
}
