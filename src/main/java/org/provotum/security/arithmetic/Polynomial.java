package org.provotum.security.arithmetic;

import java.util.ArrayList;
import java.util.List;

public class Polynomial {

    private ModInteger p;
    private ModInteger q;
    private ModInteger g;

    private int degree;
    private List<ModInteger> coefficients;

    public Polynomial(ModInteger p, ModInteger q, ModInteger g, int degree) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.degree = degree;

        this.coefficients = new ArrayList<>();

        for (int i = 0; i <= this.degree; i++) {
            coefficients.add(ModInteger.random(this.q));
        }
    }

    public Polynomial(ModInteger p, ModInteger q, ModInteger g, List<ModInteger> coefficients) {
        this.p = p;
        this.q = q;
        this.g = g;
        this.coefficients = coefficients;
        this.degree = coefficients.size() - 1;
    }

    public int getDegree() {
        return degree;
    }

    public List<ModInteger> getCoefficients() {
        return coefficients;
    }

    public ModInteger evaluate(ModInteger x) {
        ModInteger sum = new ModInteger(ModInteger.ZERO, this.q);

        for (int i = 0; i < this.coefficients.size(); i++) {
            ModInteger coefficient = this.coefficients.get(i);
            sum = sum.add(coefficient.multiply(new ModInteger(x, this.q).pow(i)));
        }

        return sum;
    }

    public List<ModInteger> getLagrangeCoefficients() {
        List<ModInteger> lagrangeCoefficients = new ArrayList<>(this.coefficients.size());

        for (ModInteger next : this.coefficients) {
            ModInteger numerator = new ModInteger(ModInteger.ONE, this.q);

            for (ModInteger innerNext : this.coefficients) {
                if (!next.equals(innerNext)) {
                    numerator = numerator.multiply(this.q.subtract(innerNext));
                }
            }

            ModInteger denominator = new ModInteger(ModInteger.ONE, this.q);

            for (ModInteger innerNext : this.coefficients) {
                if (!next.equals(innerNext)) {
                    denominator = denominator.multiply(next.subtract(innerNext));
                }
            }

            lagrangeCoefficients.add(numerator.divide(denominator));
        }

        return lagrangeCoefficients;
    }
}
