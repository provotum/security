package org.provotum.security.vote;

import org.provotum.security.elgamal.CipherText;

public class Vote {

    private CipherText cipherText;

    public Vote(CipherText cipherText) {
        this.cipherText = cipherText;
    }

    public Vote multiply(Vote vote) {
        return new Vote(this.getCipherText().multiply(vote.getCipherText()));
    }

    public CipherText getCipherText() {
        return cipherText;
    }
}
