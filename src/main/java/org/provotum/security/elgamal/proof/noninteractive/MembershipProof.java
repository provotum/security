package org.provotum.security.elgamal.proof.noninteractive;

import org.provotum.security.api.IMembershipProof;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;
import org.provotum.security.serializer.ShaSerializer;

import java.util.ArrayList;
import java.util.List;

/**
 * A proof that an ElGamal encrypted value is within a particular range.
 * This proof is based on the Chaum-Pedersen protocol, made non-interactive using the Fiat-Shamir heuristic.
 */
public class MembershipProof implements IMembershipProof<CipherText> {

    private final List<ModInteger> sResponses;
    private final List<ModInteger> cResponses;
    private final List<ModInteger> yResponses;
    private final List<ModInteger> zResponses;

    private final ModInteger p;
    private final ModInteger q;

    /**
     * @param publicKey        The public key used during encryption.
     * @param plainTextMessage The plaintext message which is encrypted.
     * @param cipherText       The ciphertext encrypting the plaintext message.
     * @param domains          A list of values the plaintext message can take on.
     * @return A proof, that the plaintext message is within the given domain.
     */
    public static MembershipProof commit(PublicKey publicKey, ModInteger plainTextMessage, CipherText cipherText, List<ModInteger> domains) {
        // Holds the first response from the prover to the verifier
        List<ModInteger> yResponses = new ArrayList<>();
        List<ModInteger> zResponses = new ArrayList<>();
        // Holds the second response from the prover to the verifier
        List<ModInteger> sResponses = new ArrayList<>();
        List<ModInteger> cResponses = new ArrayList<>();

        // create the generator g and the public value of the private key
        // relative to the prime modulus p.
        ModInteger g = new ModInteger(publicKey.getG(), publicKey.getP());
        ModInteger h = new ModInteger(publicKey.getH(), publicKey.getP());

        // generate a random value we use
        // while committing to the real vote
        ModInteger t = ModInteger.random(publicKey.getQ());

        // Create a string representation of
        StringBuilder sb = new StringBuilder(4096);
        sb.append(g);
        sb.append(h);
        sb.append(cipherText.getG());
        sb.append(cipherText.getH());

        // the index of the domain of the message within
        // the list of all allowed domain values
        int messageIndex = 0;

        // for all values the cleartext message
        // could possibly take on, we either generate a fake commitment
        // or the real commitment (in case the domain is equal to the plaintext message)
        for (int i = 0; i < domains.size(); i++) {
            ModInteger y;
            ModInteger z;
            ModInteger domainValue = domains.get(i);

            if (domainValue.equals(plainTextMessage)) {
                // add fake values, will be set after we got the challenge
                sResponses.add(ModInteger.ZERO);
                cResponses.add(ModInteger.ZERO);

                // create according to one execution of the Schnorr protocol
                y = g.pow(t);
                z = h.pow(t);

                messageIndex = i;
            } else {
                // add fake commitments as well as the corresponding response
                // for a value which is not the plaintext message
                ModInteger s = ModInteger.random(publicKey.getQ());
                ModInteger c = ModInteger.random(publicKey.getQ());

                sResponses.add(s);
                cResponses.add(c);

                ModInteger negC = c.negate();

                // map the value of the domain into the group used for the message.
                ModInteger gPow = g.pow(domainValue);

                // Simulate values according to the Schnorr protocol for fake values
                // y = g^s * G^(-c)
                y = g.pow(s).multiply(cipherText.getG().pow(negC));
                // z = h^s * (H / g)^(-c)
                z = h.pow(s).multiply(cipherText.getH().divide(gPow).pow(negC));
            }

            // Add the initial commitment values
            yResponses.add(y);
            zResponses.add(z);

            sb.append(y);
            sb.append(z);
        }

        // Use the Fiat-Shamir heuristic to create a random oracle
        String s = sb.toString();
        String cHash = ShaSerializer.toSha512HexString(s);

        // Create a numeric value from the hash
        // and let's assume that realC is the challenge we received from the verifier
        ModInteger c0 = new ModInteger(cHash, publicKey.getQ(), 16).mod(publicKey.getQ());

        //  Subtract all fake c from the real one.
        for (ModInteger fakeC : cResponses) {
            c0 = c0.subtract(fakeC);
        }

        // Calculate the correct s as described in the Schnorr protocol:
        // s = t0 + c0 * r
        sResponses.set(messageIndex, c0.multiply(cipherText.getR()).add(t));

        // eventually set the commitment value for the correct message.
        cResponses.set(messageIndex, c0);

        return new MembershipProof(publicKey.getP(), publicKey.getQ(), yResponses, zResponses, sResponses, cResponses);
    }

    /**
     * Crate a membership proof that the sum of two messages is correct.
     *
     * @param publicKey   The public key used during encryption.
     * @param cipherText1 The first encrypted message.
     * @param proof1      The proof of the first encrypted message, that it encodes the correct values.
     * @param cipherText2 The second encrypted message.
     * @param proof2      The proof of the second encrypted message that it encodes the correct value.
     * @param domain      The domain of the sum (i.e. all possible values the sum may have if both ciphertexts hold any of their domain values)
     * @return The proof that the plaintext sum of both ciphertexts is within the specified domain.
     */
    public static MembershipProof commitToSum(PublicKey publicKey, CipherText cipherText1, MembershipProof proof1, CipherText cipherText2, MembershipProof proof2, List<ModInteger> domain) {
        List<ModInteger> sResponses = new ArrayList<>();
        List<ModInteger> cResponses = new ArrayList<>();
        List<ModInteger> yResponses = new ArrayList<>();
        List<ModInteger> zResponses = new ArrayList<>();

        // create the generator g and the public value of the private key
        // relative to the prime modulus p.
        ModInteger g = new ModInteger(publicKey.getG(), publicKey.getP());
        ModInteger h = new ModInteger(publicKey.getH(), publicKey.getP());

        // apply the multiplication of both ciphertexts
        // i.e. in additive ElGamal this is the sum of the plaintext values
        ModInteger bigG = cipherText1.getG().multiply(cipherText2.getG());
        ModInteger bigH = cipherText1.getH().multiply(cipherText2.getH());

        int messageIndex = 0;

        // generate a random value we use
        // while committing to the real vote
        ModInteger t = ModInteger.random(publicKey.getQ());

        StringBuilder sb = new StringBuilder(4096);
        sb.append(g);
        sb.append(h);
        sb.append(bigG);
        sb.append(bigH);

        // shift the domains so that stuff works...
        List<ModInteger> newCResponses1 = new ArrayList<>();
        List<ModInteger> newSResponses1 = new ArrayList<>();
        ModInteger min1 = ModInteger.ZERO;
        ModInteger max1 = ModInteger.ONE;

        List<ModInteger> newCResponses2 = new ArrayList<>();
        List<ModInteger> newSResponses2 = new ArrayList<>();
        ModInteger min2 = ModInteger.ZERO;
        ModInteger max2 = ModInteger.ONE;

        int j = 0;
        int k = 0;

        for (int i = domain.get(0).intValue(); i <= domain.get(domain.size() - 1).intValue(); i++) {
            if (i < min1.intValue() || i > max1.intValue()) {
                newCResponses1.add(ModInteger.random(publicKey.getQ()));
                newSResponses1.add(ModInteger.random(publicKey.getQ()));
            } else {
                newCResponses1.add(proof1.cResponses.get(j));
                newSResponses1.add(proof1.sResponses.get(j));
                j++;
            }

            if (i < min2.intValue() || i > max2.intValue()) {
                newCResponses2.add(ModInteger.random(publicKey.getQ()));
                newSResponses2.add(ModInteger.random(publicKey.getQ()));
            } else {
                newCResponses2.add(proof2.cResponses.get(k));
                newSResponses2.add(proof2.sResponses.get(k));
                k++;
            }
        }

        // for all values the cleartext message
        // could possibly take on, we either generate a fake commitment
        // or the real commitment (in case the domain is equal to the plaintext message)
        for (int i = 0; i < domain.size(); i++) {
            ModInteger y;
            ModInteger z;
            ModInteger domainValue = domain.get(i);

            ModInteger gPow = g.pow(domainValue);

            // is the domain equal to the message?
            if (bigH.divide(gPow).equals(h.pow(cipherText1.getR().add(cipherText2.getR())))) {
                y = g.pow(t);
                z = h.pow(t);
                cResponses.add(ModInteger.ZERO);
                sResponses.add(ModInteger.ZERO);
                messageIndex = i;
            } else {
                ModInteger s1 = newSResponses1.get(i);
                ModInteger s2 = newSResponses2.get(i);

                ModInteger c1 = newCResponses1.get(i);
                ModInteger c2 = newCResponses2.get(i);

                // s = s1 + s2
                sResponses.add(s1.add(s2));

                // c = c1 + c2
                cResponses.add(c1.add(c2));

                ModInteger negC1 = c1.negate();
                ModInteger negC2 = c2.negate();

                // create according to one execution of the Schnorr protocol
                // i.e g^s1 * G1^(-c1)
                // i.e g^s2 * G2^(-c2)
                ModInteger y1 = g.pow(s1).multiply(cipherText1.getG().pow(negC1));
                ModInteger y2 = g.pow(s2).multiply(cipherText2.getG().pow(negC2));

                // y = (y1 * y2) / ( g^(r2 * c1 + r2 * c2) )
                y = y1.multiply(y2).divide(g.pow(cipherText2.getR().multiply(c1).add(cipherText1.getR().multiply(c2))));

                // z1 = h^s1 * (H1 / g^(-c1) )
                // z2 = h^s2 * (H2 / g^(-c2) )
                ModInteger z1 = h.pow(s1).multiply(cipherText1.getH().divide(gPow).pow(negC1));
                ModInteger z2 = h.pow(s2).multiply(cipherText2.getH().divide(gPow).pow(negC2));

                // z = z1 * z2 / ( (H2^c1 * H1^c2)
                z = z1.multiply(z2).divide(cipherText2.getH().pow(c1).multiply(cipherText1.getH().pow(c2)));
            }

            yResponses.add(y);
            zResponses.add(z);

            sb.append(y);
            sb.append(z);
        }

        // Use the Fiat-Shamir heuristic to create a random oracle
        String s = sb.toString();
        String cHash = ShaSerializer.toSha512HexString(s);

        // Create a numeric value from the hash
        // and let's assume that realC is the challenge we received from the verifier
        ModInteger c0 = new ModInteger(cHash, publicKey.getQ(), 16).mod(publicKey.getQ());

        //  Subtract all fake c from the real one.
        for (ModInteger fakeC : cResponses) {
            c0 = c0.subtract(fakeC);
        }

        // Calculate the correct s as described in the Schnorr protocol:
        // s = t0 + c0 * r
        sResponses.set(messageIndex, c0.multiply(cipherText1.getR().add(cipherText2.getR())).add(t));

        // eventually set the commitment value for the correct message.
        cResponses.set(messageIndex, c0);

        return new MembershipProof(publicKey.getP(), publicKey.getQ(), yResponses, zResponses, sResponses, cResponses);
    }


    /**
     * @param p          The prime used during encryption of the ciphertext for which this proof should be made.
     * @param q          The value q, which is in relation to p in the form of q = (p-1)/2.
     * @param yResponses The list of y values used during the commitment phase of the proof.
     * @param zResponses The list of z values used during the commitment phase of the proof.
     * @param sResponses The list of s values used during the commitment phase of the proof.
     * @param cResponses The list of commitments created during the commitment phase of the proof.
     */
    public MembershipProof(ModInteger p, ModInteger q, List<ModInteger> yResponses, List<ModInteger> zResponses, List<ModInteger> sResponses, List<ModInteger> cResponses) {
        this.p = p;
        this.q = q;

        this.yResponses = yResponses;
        this.zResponses = zResponses;
        this.sResponses = sResponses;
        this.cResponses = cResponses;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(PublicKey publicKey, CipherText cipherText, List<ModInteger> domain) {
        if (domain.size() < this.cResponses.size() ||
            domain.size() < this.sResponses.size()) {
            // The domain of the message is bigger than specified.
            // Therefore, the proof that the message is within the given domain is invalid.
            return false;
        }

        ModInteger g = new ModInteger(publicKey.getG(), p);
        ModInteger h = new ModInteger(publicKey.getH(), p);

        // create the generator g and the public value of the private key
        // relative to the prime modulus p.
        ModInteger bigG = cipherText.getG();
        ModInteger bigH = cipherText.getH();

        // The commit value we are trying to reconstruct
        ModInteger cChoices = new ModInteger(ModInteger.ZERO, q);

        StringBuilder sb = new StringBuilder(4096);
        sb.append(g);
        sb.append(h);
        sb.append(bigG);
        sb.append(bigH);

        // For all domains the message could take on we have to check its commitments
        for (int i = 0; i < cResponses.size(); i++) {
            ModInteger domainValue = domain.get(i);

            ModInteger gPow = g.pow(domainValue);

            ModInteger s = sResponses.get(i);
            ModInteger c = cResponses.get(i);
            ModInteger negC = c.negate();

            // reconstruct the realC
            cChoices = cChoices.add(c);

            // g^s * G^(-c)
            sb.append(g.pow(s).multiply(bigG.pow(negC)));
            // h^s * ( H / (g^-c) )
            sb.append(h.pow(s).multiply(bigH.divide(gPow).pow(negC)));
        }

        // reconstruct the hash
        String cHash = ShaSerializer.toSha512HexString(sb.toString());
        ModInteger newC = new ModInteger(cHash, q, 16).mod(q);

        // the proof is valid if the reconstructed c is equal to the
        // value we initially created the commitment from
        return (cChoices.equals(newC));


    }

    public List<ModInteger> getsResponses() {
        return sResponses;
    }

    public List<ModInteger> getcResponses() {
        return cResponses;
    }

    public List<ModInteger> getyResponses() {
        return yResponses;
    }

    public List<ModInteger> getzResponses() {
        return zResponses;
    }

    public ModInteger getP() {
        return p;
    }

    public ModInteger getQ() {
        return q;
    }
}
