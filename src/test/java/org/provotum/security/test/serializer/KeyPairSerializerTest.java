package org.provotum.security.test.serializer;

import junit.framework.TestCase;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.provotum.security.elgamal.PrivateKey;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.serializer.KeyPairSerializer;

import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class KeyPairSerializerTest extends TestCase {

    private static final int EL_GAMAL_KEY_LENGTH = 160;

    private PublicKey publicKey;
    private PrivateKey privateKey;

    @Override
    public void setUp() throws Exception {
        super.setUp();

        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.init(EL_GAMAL_KEY_LENGTH, 20, new SecureRandom());
        ElGamalParameters parameters = generator.generateParameters();

        ElGamalParameterSpec elGamalParameterSpec = new ElGamalParameterSpec(parameters.getP(), parameters.getG());

        KeyPairGeneratorSpi keyPairGeneratorSpi = new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();
        keyPairGeneratorSpi.initialize(elGamalParameterSpec, new SecureRandom());

        KeyPair keyPair = keyPairGeneratorSpi.generateKeyPair();

        ElGamalPublicKey pubKey = (ElGamalPublicKey) keyPair.getPublic();
        ElGamalPrivateKey privKey = (ElGamalPrivateKey) keyPair.getPrivate();

        this.publicKey = new PublicKey(pubKey);
        this.privateKey = new PrivateKey(privKey);
    }

    public void testPublicKeySerialization() {
        String publicKey = KeyPairSerializer.serializePublicKey(this.publicKey);
        PublicKey restoredPublicKey = KeyPairSerializer.publicKeyFromString(publicKey);

        assertEquals(this.publicKey, restoredPublicKey);
    }

    public void testPrivateKeySerialization() {
        String privateKey = KeyPairSerializer.serializePrivateKey(this.privateKey);
        PrivateKey restoredPrivateKey = KeyPairSerializer.privateKeyFromString(privateKey);

        assertEquals(this.privateKey, restoredPrivateKey);
    }
}
