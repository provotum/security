package org.provotum.security.api;

public class AProofedCipherText<C extends IHomomorphicCipherText<C>, P extends IMembershipProof<C>> {

    private C cipherText;
    private P proof;

    public static AProofedCipherText fromString(String string) {

        return null;
    }

    public AProofedCipherText(C cipherText, P proof) {
        this.cipherText = cipherText;
        this.proof = proof;
    }

    public C getCipherText() {
        return cipherText;
    }

    public P getProof() {
        return proof;
    }

    public String toString() {
        StringBuilder sb = new StringBuilder();

        sb.append("ciphertext");
        sb.append(this.cipherText.toString());

        sb.append("proof");
        sb.append(this.proof.toString());

        return sb.toString();
    }
}
