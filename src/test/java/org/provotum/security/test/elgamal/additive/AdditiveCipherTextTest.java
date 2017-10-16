package org.provotum.security.test.elgamal.additive;

import junit.framework.TestCase;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.provotum.security.api.IEncryption;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PrivateKey;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;
import org.provotum.security.elgamal.additive.Encryption;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.KeyPairGeneratorSpi;
import java.security.SecureRandom;

/**
 * Tests the correct working of additive ElGamal homomorphic encryption.
 */
public class AdditiveCipherTextTest extends TestCase {

    private PublicKey publicKey;
    private PrivateKey privateKey;

    private IEncryption<CipherText> encryption;

    public void setUp() throws InvalidAlgorithmParameterException {
        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.init(160, 20, new SecureRandom());
        ElGamalParameters parameters = generator.generateParameters();
        parameters.getP(); // public prime
        parameters.getG(); // public generator

        ElGamalParameterSpec elGamalParameterSpec = new ElGamalParameterSpec(parameters.getP(), parameters.getG());

        KeyPairGeneratorSpi keyPairGeneratorSpi = new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();
        keyPairGeneratorSpi.initialize(elGamalParameterSpec, new SecureRandom());

        KeyPair keyPair = keyPairGeneratorSpi.generateKeyPair();

        ElGamalPublicKey pubKey = (ElGamalPublicKey) keyPair.getPublic();
        ElGamalPrivateKey privKey = (ElGamalPrivateKey) keyPair.getPrivate();

        this.publicKey = new PublicKey(pubKey);
        this.privateKey = new PrivateKey(privKey);

        this.encryption = new Encryption();
    }

    public void testAddition() {
        CipherText cipherText1 = this.encryption.encrypt(this.publicKey, ModInteger.ONE);
        CipherText cipherText2 = this.encryption.encrypt(this.publicKey, ModInteger.ONE);

        // should contain value for two
        CipherText cipherText = cipherText1.multiply(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertEquals(new BigInteger("2"), result.getValue());
        assertEquals(BigInteger.ZERO, result.getModulus());
    }

    public void testAddition2() {
        CipherText cipherText1 = this.encryption.encrypt(this.publicKey, ModInteger.ONE);
        CipherText cipherText2 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);

        // should contain value for one
        CipherText cipherText = cipherText1.multiply(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertEquals(BigInteger.ONE, result.getValue());
        assertEquals(BigInteger.ZERO, result.getModulus());
    }

    public void testAddition3() {
        CipherText cipherText1 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);
        CipherText cipherText2 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);

        // should contain value for one
        CipherText cipherText = cipherText1.multiply(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertEquals(BigInteger.ZERO, result.getValue());
        assertEquals(BigInteger.ZERO, result.getModulus());
    }
}
