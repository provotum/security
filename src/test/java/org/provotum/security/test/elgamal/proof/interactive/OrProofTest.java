package org.provotum.security.test.elgamal.proof.interactive;

import junit.framework.TestCase;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.junit.Ignore;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;
import org.provotum.security.elgamal.additive.Encryption;
import org.provotum.security.elgamal.proof.interactive.OrProof;
import org.provotum.security.elgamal.proof.interactive.Response;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class OrProofTest extends TestCase {

    private PublicKey publicKey;

    public void setUp() {
        ElGamalPublicKey epk = new ElGamalPublicKey() {
            @Override
            public BigInteger getY() {
                // public key value
                return new BigInteger("4");
            }

            @Override
            public String getAlgorithm() {
                return null;
            }

            @Override
            public String getFormat() {
                return null;
            }

            @Override
            public byte[] getEncoded() {
                return new byte[0];
            }

            @Override
            public ElGamalParameterSpec getParameters() {
                // Prime p = 5
                // Generator g = 2
                return new ElGamalParameterSpec(new BigInteger("5"), new BigInteger("2"));
            }

            @Override
            public DHParameterSpec getParams() {
                return null;
            }
        };


        this.publicKey = new PublicKey(epk);
    }

    public void testOrProof() {
        // message must be in the base of the prime number p
        ModInteger message = new ModInteger(1, this.publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        OrProof proof = new OrProof(cipherText, this.publicKey);
        proof.commit();

        ModInteger challenge = new ModInteger(1, publicKey.getP());
        Response response = proof.challenge(challenge);

        boolean isProven = proof.verify(challenge, response);

        assertTrue(isProven);
    }
}
