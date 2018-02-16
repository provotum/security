package org.provotum.security.elgamal.proof.noninteractive;

import org.provotum.security.Util;
import org.provotum.security.api.IMembershipProof;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;

import java.util.ArrayList;
import java.util.List;

/**
 * A proof that an ElGamal encrypted value is within a particular range.
 */
public class MembershipProof implements IMembershipProof<CipherText> {

    private final List<ModInteger> sList;
    private final List<ModInteger> cList;
    private final List<ModInteger> yList;
    private final List<ModInteger> zList;

    private final ModInteger p;
    private final ModInteger q;


    public static MembershipProof commit(PublicKey publicKey, ModInteger plainTextMessage, CipherText cipherText, List<ModInteger> domain) {
        List<ModInteger> sList = new ArrayList<>();
        List<ModInteger> cList = new ArrayList<>();
        List<ModInteger> yList = new ArrayList<>();
        List<ModInteger> zList = new ArrayList<>();


        // create the generator g and the public value of the private key
        // relative to the prime modulus p.
        ModInteger g = new ModInteger(publicKey.getG(), publicKey.getP());
        ModInteger h = new ModInteger(publicKey.getH(), publicKey.getP());

        // generate a random value we use while committing
        // to the real vote
        ModInteger t = ModInteger.random(publicKey.getQ());

        // Create a string representation of
        StringBuilder sb = new StringBuilder(4096);
        sb.append(g);
        sb.append(h);
        sb.append(cipherText.getG());
        sb.append(cipherText.getH());

        // the index of the domain of the message within
        // the list of all allowed domain values
        int indexInDomain = 0;


        /* Iterate over the domain */
        for (int i = 0; i < domain.size(); i++) {

            ModInteger y;
            ModInteger z;
            ModInteger d = domain.get(i);

            /* See if the value is this particular member of the domain */
            if (d.equals(plainTextMessage)) {

                /* If it is, fill c_i and s_i with dummy values for now */
                sList.add(ModInteger.ZERO);
                cList.add(ModInteger.ZERO);

                /* Compute random group member */
                y = g.pow(t);

                /* commit a random cipher, as part of the commitment process */
                z = h.pow(t);

                /* Record the index of the valid value */
                indexInDomain = i;
            } else {

                /* If we don't have a valid value, generate random numbers for c_i and s_i */
                sList.add(ModInteger.random(publicKey.getQ()));
                cList.add(ModInteger.random(publicKey.getQ()));
                ModInteger s = sList.get(i);
                ModInteger c = cList.get(i);

                /* This will be needed for computing z_i */
                ModInteger negC = c.negate();

                /* This is essentially the message corresponding to domain member d mapped into G */
                ModInteger fpow = g.pow(d);

                /* Compute a group member g^s * (g^r)^(-c_i) = g^(s - r*c_i) */
                y = g.pow(s).multiply(cipherText.getG().pow(negC));

                /* Compute a cipher, of the form g^xs * [(g^rx * f^m)/f^d]^(-c_i) = g^[x(s - rc_i)] * f^[c_i*(d - m)] */
                z = h.pow(s).multiply(cipherText.getH().divide(fpow).pow(negC));
            }

            /* Add our random ciphers and members to their respective lists */
            yList.add(y);
            zList.add(z);

            /* Add them to the commitment string */
            sb.append(y);
            sb.append(z);
        }

        /* Hash the commitment string */
        String s = sb.toString();
        String cHash = Util.sha1(s);

        /* From the hash, construct a numerical value */
        ModInteger c1 = new ModInteger(cHash, publicKey.getQ(), 16).mod(publicKey.getQ());
        ModInteger realC = new ModInteger(c1, publicKey.getQ());

        /* Now subtract all of the generated fake commits off the hash value (note, the valid value will still be 0 here) */
        for (ModInteger fakeC : cList) {
            realC = realC.subtract(fakeC);
        }

        /* Note that realC (call it p) is now c1 - (sum(cList)) */

        /* Compute pr + t using our real commitment value and add it in the right place */
        sList.set(indexInDomain, realC.multiply(cipherText.getR()).add(t));

        /* Add our real commitment value into the commit list in the right place */
        cList.set(indexInDomain, realC);

        return new MembershipProof(publicKey.getP(), publicKey.getQ(), yList, zList, sList, cList);
    }


    /**
     * @param p     The prime used during encryption of the ciphertext for which this proof should be made.
     * @param q     The value q, which is in relation to p in the form of q = (p-1)/2.
     * @param yList The list of y values used during the commitment phase of the proof.
     * @param zList The list of z values used during the commitment phase of the proof.
     * @param sList The list of s values used during the commitment phase of the proof.
     * @param cList The list of commitments created during the commitment phase of the proof.
     */
    public MembershipProof(ModInteger p, ModInteger q, List<ModInteger> yList, List<ModInteger> zList, List<ModInteger> sList, List<ModInteger> cList) {
        this.p = p;
        this.q = q;

        this.yList = yList;
        this.zList = zList;
        this.sList = sList;
        this.cList = cList;
    }


    /**
     * {@inheritDoc}
     */
    @Override
    public boolean verify(PublicKey publicKey, CipherText cipherText, List<ModInteger> domain) {
        if (domain.size() < this.cList.size() ||
            domain.size() < this.sList.size()) {
            // The domain of the message is bigger than specified.
            // Therefore, the proof that the message is within the given domain is invalid.
            return false;
        }

        /* Extract necessary key components for computation */
        ModInteger g = new ModInteger(publicKey.getG(), p);
        ModInteger h = new ModInteger(publicKey.getH(), p);

        /* Get the cipher's randomness and encrypted value*/
        /* bigG (g^r), bigH (g^(rx) * f^m) */
        ModInteger bigG = cipherText.getG();
        ModInteger bigH = cipherText.getH();

        /* This will be our commit value that we reconstruct */
        ModInteger cChoices = new ModInteger(ModInteger.ZERO, q);

        /* Build a new commit string so we can reconstruct our commit value */
        StringBuilder sb = new StringBuilder(4096);

        /* start the string off the right way */
        sb.append(g);
        sb.append(h);
        sb.append(bigG);
        sb.append(bigH);

        try {
            /* Iterate over all the commits, fake and otherwise */
            for (int i = 0; i < cList.size(); i++) {

                /* Get out the domain value (i.e. the possible message m) */
                ModInteger d = domain.get(i);

                /* Map the value into the group via f */
                ModInteger fpow = g.pow(d);


                /* extract the commit value and cr + t (or the random values) */
                ModInteger s = sList.get(i);
                ModInteger c = cList.get(i);

                /* Compute -c_i so it will fall out of z_i for fake commitments */
                ModInteger negC = c.negate();

                /*
                 * add this commit value to reconstruct our hashed value
                 * cChoices = sum(c_i), where one c_i is realC from commit, giving us
                 * cChoices = c_0 + ... + realC + ... c_n = c_0 + ... (c1 - (c_0 + ... + 0 + ... + c_n) + ... c_n
                 * cChoices = c_0 - c_0 + ... c - 0 + ... c_n - c_n
                 * cChoices = c1 eventually
                 */
                cChoices = cChoices.add(c);

                /* Compute the y-values used in the commit string */
                sb.append(g.pow(s).multiply(bigG.pow(negC)));

                /* Compute the z-values used in the commit string */
                sb.append(h.pow(s).multiply(bigH.divide(fpow).pow(negC)));
            }

            /* Now take the hash of the commit string and convert it to a number */
            String cHash = Util.sha1(sb.toString());
            ModInteger newC = new ModInteger(cHash, q, 16).mod(q);

            /* Ensure that cChoices (i.e. the real commit) matches the hashed value of the commit string */
            return (cChoices.equals(newC));

        } catch (IndexOutOfBoundsException e) {
            /* This happens if the domain used in verification is smaller than the
             * one used for computation of the proof -- automatic failure for verification
             */
            return false;
        }
    }

    public List<ModInteger> getsList() {
        return sList;
    }

    public List<ModInteger> getcList() {
        return cList;
    }

    public List<ModInteger> getyList() {
        return yList;
    }

    public List<ModInteger> getzList() {
        return zList;
    }

    public ModInteger getP() {
        return p;
    }

    public ModInteger getQ() {
        return q;
    }
}
