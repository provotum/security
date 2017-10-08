package org.provotum.security.elgamal;

import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jcajce.provider.asymmetric.elgamal.*;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.KeyPairGeneratorSpi;

public class Main {

    public static void main(String... args) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.addProvider(new BouncyCastleProvider());
        }

        ElGamalParametersGenerator generator = new ElGamalParametersGenerator();
        generator.init(1024, 20, new SecureRandom());
        ElGamalParameters parameters = generator.generateParameters();
        parameters.getP(); // public prime
        parameters.getG(); // public generator

        ElGamalParameterSpec elGamalParameterSpec = new ElGamalParameterSpec(parameters.getP(), parameters.getG());

        KeyPairGeneratorSpi keyPairGeneratorSpi = new org.bouncycastle.jcajce.provider.asymmetric.elgamal.KeyPairGeneratorSpi();
        keyPairGeneratorSpi.initialize(elGamalParameterSpec, new SecureRandom());

        KeyPair keyPair = keyPairGeneratorSpi.generateKeyPair();

        ElGamalPublicKey pubKey = (ElGamalPublicKey) keyPair.getPublic();
        ElGamalPrivateKey privKey = (ElGamalPrivateKey) keyPair.getPrivate();

        String s = "Hello";

        ElGamalEncryption enc = new ElGamalEncryption();
        byte[] encrypted = enc.encrypt(pubKey, s.getBytes(StandardCharsets.UTF_8));

        byte[] decrypted = enc.decrypt(privKey, encrypted);

        System.out.println(new String(decrypted, StandardCharsets.UTF_8));
    }
}
