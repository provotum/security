package org.provotum.security.test.elgamal.proof.noninteractive;

import junit.framework.TestCase;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;
import org.provotum.security.elgamal.additive.Encryption;
import org.provotum.security.elgamal.proof.noninteractive.MembershipProof;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class MembershipProofTest extends TestCase {

    private PublicKey publicKey;
    private List<ModInteger> domain;

    public void setUp() throws InvalidAlgorithmParameterException {
        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.init(160, 20, new SecureRandom());
        ElGamalParameters parameters = generator.generateParameters();

        ElGamalParameterSpec elGamalParameterSpec = new ElGamalParameterSpec(parameters.getP(), parameters.getG());

        KeyPairGeneratorSpi keyPairGeneratorSpi = new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();
        keyPairGeneratorSpi.initialize(elGamalParameterSpec, new SecureRandom());

        KeyPair keyPair = keyPairGeneratorSpi.generateKeyPair();

        ElGamalPublicKey pubKey = (ElGamalPublicKey) keyPair.getPublic();

        this.publicKey = new PublicKey(pubKey);

        this.domain = new ArrayList<>();
        this.domain.add(ModInteger.ZERO);
        this.domain.add(ModInteger.ONE);
    }

    public void testOneOrProof() {
        // message must be in the base of the prime number p
        ModInteger message = new ModInteger(1, this.publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        MembershipProof proof = MembershipProof.commit(
            this.publicKey,
            message,
            cipherText,
            this.domain
        );

        boolean isProven = proof.verify(this.publicKey, cipherText, this.domain);

        assertTrue(isProven);
    }

    public void testFailedOneOrProof() {
        // message must be in the base of the prime number p
        ModInteger message = new ModInteger(1, this.publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        MembershipProof proof = MembershipProof.commit(
            this.publicKey,
            ModInteger.ZERO, // wrong message -> verifying the proof should fail
            cipherText,
            this.domain
        );

        boolean isProven = proof.verify(this.publicKey, cipherText, this.domain);

        assertFalse(isProven);
    }

    public void testZeroOrProof() {
        // message must be in the base of the prime number p
        ModInteger message = new ModInteger(0, this.publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        MembershipProof proof = MembershipProof.commit(
            this.publicKey,
            message,
            cipherText,
            this.domain
        );

        boolean isProven = proof.verify(this.publicKey, cipherText, this.domain);

        assertTrue(isProven);
    }

    public void testFailedZeroOrProof() {
        // message must be in the base of the prime number p
        ModInteger message = new ModInteger(0, this.publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        MembershipProof proof = MembershipProof.commit(
            this.publicKey,
            ModInteger.ONE, // verifying should fail since not the correct message for which the proof was generated
            cipherText,
            this.domain
        );
        boolean isProven = proof.verify(this.publicKey, cipherText, this.domain);

        assertFalse(isProven);
    }

    public void testOutOfBoundOrProof() {
        // message must be in the base of the prime number p
        ModInteger message = new ModInteger(3, this.publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        MembershipProof proof = MembershipProof.commit(
            this.publicKey,
            message, // message is out of the domain, therefore verifying should fail
            cipherText,
            this.domain
        );

        boolean isProven = proof.verify(this.publicKey, cipherText, this.domain);

        assertFalse(isProven);
    }
}
