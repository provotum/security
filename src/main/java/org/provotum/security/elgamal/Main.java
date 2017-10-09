package org.provotum.security.elgamal;

import org.bouncycastle.crypto.generators.ElGamalParametersGenerator;
import org.bouncycastle.crypto.params.ElGamalParameters;
import org.bouncycastle.jce.interfaces.ElGamalPrivateKey;
import org.bouncycastle.jce.interfaces.ElGamalPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ElGamalParameterSpec;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.arithmetic.Polynomial;
import org.provotum.security.election.Election;
import org.provotum.security.vote.Vote;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.util.ArrayList;
import java.util.List;

public class Main {

    public static void main(String... args) throws NoSuchProviderException, NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, InvalidAlgorithmParameterException {
        if (null == Security.getProvider(BouncyCastleProvider.PROVIDER_NAME)) {
            Security.addProvider(new BouncyCastleProvider());
        }

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

        String s = "Hello";

        Encryption enc = new Encryption();
        byte[] encrypted = enc.encrypt(pubKey, s.getBytes(StandardCharsets.UTF_8));

        byte[] decrypted = enc.decrypt(privKey, encrypted);

        System.out.println(new String(decrypted, StandardCharsets.UTF_8));


        System.out.println("-------------------------------");
        PublicKey publicKey = new PublicKey(pubKey);
        PrivateKey privateKey = new PrivateKey(privKey);

        Vote vote = new Vote(CipherText.encrypt(publicKey, ModInteger.ONE));

        Election election = new Election(publicKey);
        election.castVote(vote);
        Vote cipherSum = election.sumVotes();
        ModInteger partial = privateKey.partialDecrypt(cipherSum.getCipherText());
        List<ModInteger> sums = new ArrayList<>();
        sums.add(partial);

        ArrayList<ModInteger> coeffs = new ArrayList<>();
        coeffs.add(ModInteger.ZERO); // must be the index of the authority if multiple

        ModInteger result = election.getFinalSum(sums, coeffs, cipherSum, publicKey);

        System.out.println(result);
    }
}
