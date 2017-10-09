package org.provotum.security.random;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Random;

/**
 * A context for configuring the random generator.
 */
public final class Context {

    private final Random random;

    public Context() {
        try {
            this.random = SecureRandom.getInstance("SHA1PRNG");
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException(e);
        }
    }

    public Random getRandom() {
        return random;
    }
}