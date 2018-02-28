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
import org.provotum.security.serializer.CipherTextSerializer;

import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

public class CipherTextSerializerTest extends TestCase {

    private CipherText cipherText;

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
        this.cipherText = enc.encrypt(publicKey, message);
    }

    public void testSerialization() {
        String serializedCiphertext = CipherTextSerializer.serialize(this.cipherText);
        CipherText deserializedCiphertext = CipherTextSerializer.fromString(serializedCiphertext);

        assertEquals(this.cipherText.getG().getValue(), deserializedCiphertext.getG().getValue());
        assertEquals(this.cipherText.getG().getModulus(), deserializedCiphertext.getG().getModulus());
        assertEquals(this.cipherText.getH().getValue(), deserializedCiphertext.getH().getValue());
        assertEquals(this.cipherText.getH().getModulus(), deserializedCiphertext.getH().getModulus());

        // We are not allowed to serialize the random value of the ciphertext!
        // So during deserialization, the random value will be set to null.
        assertNull(deserializedCiphertext.getR());
    }


}
