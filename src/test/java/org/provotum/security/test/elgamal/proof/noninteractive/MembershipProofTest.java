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
        ModInteger message = new ModInteger(ModInteger.ONE, this.publicKey.getP());

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
        ModInteger message = new ModInteger(ModInteger.ONE, this.publicKey.getP());

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
        ModInteger message = new ModInteger(ModInteger.ZERO, this.publicKey.getP());

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
        ModInteger message = new ModInteger(ModInteger.ZERO, this.publicKey.getP());

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
        ModInteger message = new ModInteger("3", this.publicKey.getP());

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

    public void testProofOfSum() {
        Encryption enc = new Encryption();

        List<ModInteger> msgDomain = new ArrayList<>();
        msgDomain.add(ModInteger.ZERO);
        msgDomain.add(ModInteger.ONE);

        ModInteger message1 = new ModInteger("1", this.publicKey.getP());
        CipherText cipherText1 = enc.encrypt(this.publicKey, message1);
        MembershipProof proof1 = MembershipProof.commit(this.publicKey, ModInteger.ONE, cipherText1, msgDomain);

        ModInteger message2 = new ModInteger("1", this.publicKey.getP());
        CipherText cipherText2 = enc.encrypt(this.publicKey, message2);
        MembershipProof proof2 = MembershipProof.commit(this.publicKey, ModInteger.ONE, cipherText2, msgDomain);

        CipherText sum = cipherText1.operate(cipherText2);

        List<ModInteger> newDomain = new ArrayList<>();
        newDomain.add(ModInteger.ZERO);
        newDomain.add(ModInteger.ONE);
        newDomain.add(ModInteger.TWO);

        MembershipProof proof = MembershipProof.commitToSum(
            this.publicKey,
            cipherText1,
            proof1,
            cipherText2,
            proof2,
            newDomain
        );

        assertTrue(proof.verify(this.publicKey, sum, newDomain));
    }

}
