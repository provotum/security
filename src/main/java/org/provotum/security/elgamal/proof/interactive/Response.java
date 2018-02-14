package org.provotum.security.elgamal.proof.interactive;

import org.provotum.security.arithmetic.ModInteger;

public class Response {

    private ModInteger s0;
    private ModInteger s1;
    private ModInteger c0;
    private ModInteger c1;

    public Response(ModInteger s0, ModInteger s1, ModInteger c0, ModInteger c1) {
        this.s0 = s0;
        this.s1 = s1;
        this.c0 = c0;
        this.c1 = c1;
    }

    public ModInteger getS0() {
        return s0;
    }

    public ModInteger getS1() {
        return s1;
    }

    public ModInteger getC0() {
        return c0;
    }

    public ModInteger getC1() {
        return c1;
    }
}
