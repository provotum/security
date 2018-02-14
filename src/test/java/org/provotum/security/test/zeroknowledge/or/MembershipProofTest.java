package org.provotum.security.test.zeroknowledge.or;

import junit.framework.TestCase;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;
import org.provotum.security.elgamal.additive.Encryption;
import org.provotum.security.zeroknowledge.or.MembershipProof;
import org.provotum.security.zeroknowledge.or.OrProof;
import org.provotum.security.zeroknowledge.or.Response;

import javax.crypto.spec.DHParameterSpec;
import java.math.BigInteger;

public class MembershipProofTest extends TestCase {

    private PublicKey publicKey;
    private ModInteger message;
    private CipherText cipherText;

    public void setUp() {
        ElGamalPublicKey epk = new ElGamalPublicKey() {
            @Override
            public BigInteger getY() {
                // public key value
                // g^x = 2^2
                return new BigInteger("111");
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
                // Prime p = 7
                // Generator g = 2
                return new ElGamalParameterSpec(new BigInteger("983"), new BigInteger("258"));
            }

            @Override
            public DHParameterSpec getParams() {
                return null;
            }
        };


        this.publicKey = new PublicKey(epk);

        // message must be in the base of the prime number p
        this.message = new ModInteger(1, this.publicKey.getP());

        Encryption enc = new Encryption();
        this.cipherText = enc.encrypt(publicKey, message);
    }

    public void testOrProof() {
        MembershipProof proof = new MembershipProof(this.cipherText, this.publicKey);
        proof.compute(ModInteger.ONE);

         boolean isProven = proof.verify();

        assertTrue(isProven);
    }
}
