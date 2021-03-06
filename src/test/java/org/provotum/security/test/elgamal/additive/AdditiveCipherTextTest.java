package org.provotum.security.test.elgamal.additive;

import junit.framework.TestCase;
import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.provotum.security.api.IHomomorphicEncryption;
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

    private IHomomorphicEncryption<CipherText> encryption;

    public void setUp() throws InvalidAlgorithmParameterException {
        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.init(160, 20, new SecureRandom());
        ElGamalParameters parameters = generator.generateParameters();

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
        CipherText cipherText = cipherText1.operate(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertTrue(new BigInteger("2").equals(result.getValue().asBigInteger()));
        assertTrue(BigInteger.ZERO.equals(result.getModulus().asBigInteger()));
    }

    public void testAddition2() {
        CipherText cipherText1 = this.encryption.encrypt(this.publicKey, ModInteger.ONE);
        CipherText cipherText2 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);

        // should contain value for one
        CipherText cipherText = cipherText1.operate(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertTrue(BigInteger.ONE.equals(result.getValue().asBigInteger()));
        assertTrue(BigInteger.ZERO.equals(result.getModulus().asBigInteger()));
    }

    public void testAddition22() {
        CipherText cipherText1 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);
        CipherText cipherText2 = this.encryption.encrypt(this.publicKey, ModInteger.ONE);

        // should contain value for one
        CipherText cipherText = cipherText1.operate(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertTrue(BigInteger.ONE.equals(result.getValue().asBigInteger()));
        assertTrue(BigInteger.ZERO.equals(result.getModulus().asBigInteger()));
    }

    public void testAddition3() {
        CipherText cipherText1 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);
        CipherText cipherText2 = this.encryption.encrypt(this.publicKey, ModInteger.ZERO);

        // should contain value for one
        CipherText cipherText = cipherText1.operate(cipherText2);

        ModInteger result = this.encryption.decrypt(this.privateKey, cipherText);

        // sum should be equals to the addition of both cipher texts
        assertTrue(BigInteger.ZERO.equals(result.getValue().asBigInteger()));
        assertTrue(BigInteger.ZERO.equals(result.getModulus().asBigInteger()));
    }

    public void testClone() {
        ModInteger one = new ModInteger(BigInteger.ONE, BigInteger.TEN);
        CipherText orig = this.encryption.encrypt(this.publicKey, one);
        CipherText clone = orig.clone();

        assertFalse(orig == clone);
        assertTrue(orig.equals(clone));
    }
}
