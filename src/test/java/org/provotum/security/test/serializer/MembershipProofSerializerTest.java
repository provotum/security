package org.provotum.security.test.serializer;

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
import org.provotum.security.serializer.MembershipProofSerializer;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.List;

public class MembershipProofSerializerTest extends TestCase {

    private MembershipProof membershipProof;

    @Override
    public void setUp() throws InvalidAlgorithmParameterException {
        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.init(160, 20, new SecureRandom());
        ElGamalParameters parameters = generator.generateParameters();

        ElGamalParameterSpec elGamalParameterSpec = new ElGamalParameterSpec(parameters.getP(), parameters.getG());

        KeyPairGeneratorSpi keyPairGeneratorSpi = new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();
        keyPairGeneratorSpi.initialize(elGamalParameterSpec, new SecureRandom());

        KeyPair keyPair = keyPairGeneratorSpi.generateKeyPair();

        ElGamalPublicKey pubKey = (ElGamalPublicKey) keyPair.getPublic();

        PublicKey publicKey = new PublicKey(pubKey);

        // message must be in the base of the prime number p
        ModInteger message = new ModInteger("1", publicKey.getP());

        Encryption enc = new Encryption();
        CipherText cipherText = enc.encrypt(publicKey, message);

        List<ModInteger> domain = new ArrayList<>();
        domain.add(ModInteger.ZERO);
        domain.add(ModInteger.ONE);

        this.membershipProof = MembershipProof.commit(publicKey, message, cipherText, domain);
    }

    public void testSerialization() {
        String serializedProof = MembershipProofSerializer.serialize(this.membershipProof);
        MembershipProof deserializedProof = MembershipProofSerializer.fromString(serializedProof);

        assertEquals(this.membershipProof.getP().getValue(), deserializedProof.getP().getValue());
        assertEquals(this.membershipProof.getP().getModulus(), deserializedProof.getP().getModulus());
        assertEquals(this.membershipProof.getQ().getValue(), deserializedProof.getQ().getValue());
        assertEquals(this.membershipProof.getQ().getModulus(), deserializedProof.getQ().getModulus());

        assertEquals(this.membershipProof.getcResponses(), deserializedProof.getcResponses());
        assertEquals(this.membershipProof.getsResponses(), deserializedProof.getsResponses());
        assertEquals(this.membershipProof.getyResponses(), deserializedProof.getyResponses());
        assertEquals(this.membershipProof.getzResponses(), deserializedProof.getzResponses());
    }
}
