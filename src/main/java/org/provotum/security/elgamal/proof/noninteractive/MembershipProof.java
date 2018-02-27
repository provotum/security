package org.provotum.security.elgamal.proof.noninteractive;

import org.provotum.security.Util;
import org.provotum.security.api.IMembershipProof;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A proof that an ElGamal encrypted value is within a particular range.
 */
public class MembershipProof implements IMembershipProof<CipherText> {

    private List<ModInteger> sList;
    private List<ModInteger> cList;
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

    public static MembershipProof commitToSum(PublicKey publicKey, CipherText cipherText1, MembershipProof proof1, CipherText cipherText2, MembershipProof proof2, List<ModInteger> domain) {
        List<ModInteger> sList = new ArrayList<>();
        List<ModInteger> cList = new ArrayList<>();
        List<ModInteger> yList = new ArrayList<>();
        List<ModInteger> zList = new ArrayList<>();


        // create the generator g and the public value of the private key
        // relative to the prime modulus p.
        ModInteger g = new ModInteger(publicKey.getG(), publicKey.getP());
        ModInteger h = new ModInteger(publicKey.getH(), publicKey.getP());

        /* bigG (g^r), bigH (g^(rx) * f^m), and r */
        ModInteger bigG = cipherText1.getG().multiply(cipherText2.getG());
        ModInteger bigH = cipherText1.getH().multiply(cipherText2.getH());

        int indexInDomain = 0;

        /* Used in commitment process */
        ModInteger t = ModInteger.random(publicKey.getQ());

        StringBuilder sb = new StringBuilder(4096);

        /* Append all the numbers to the string*/
        sb.append(g);
        sb.append(h);
        sb.append(bigG);
        sb.append(bigH);

        // shift the domains so that stuff works...
        List<ModInteger> newCList1 = new ArrayList<>();
        List<ModInteger> newSList1 = new ArrayList<>();
        ModInteger min1 = ModInteger.ZERO;
        ModInteger max1 = ModInteger.ONE;

        List<ModInteger> newCList2 = new ArrayList<>();
        List<ModInteger> newSList2 = new ArrayList<>();
        ModInteger min2 = ModInteger.ZERO;
        ModInteger max2 = ModInteger.ONE;

        int j = 0;
        int k = 0;

        for (int i = domain.get(0).intValue(); i <= domain.get(domain.size() - 1).intValue(); i++) {

            if (i < min1.intValue() || i > max1.intValue()) {
                newCList1.add(ModInteger.random(publicKey.getQ()));
                newSList1.add(ModInteger.random(publicKey.getQ()));
            } else {
                newCList1.add(proof1.cList.get(j));
                newSList1.add(proof1.sList.get(j));
                j++;
            }

            if (i < min2.intValue() || i > max2.intValue()) {
                newCList2.add(ModInteger.random(publicKey.getQ()));
                newSList2.add(ModInteger.random(publicKey.getQ()));
            } else {
                newCList2.add(proof2.cList.get(k));
                newSList2.add(proof2.sList.get(k));
                k++;
            }
        }

        proof1.cList = newCList1;
        proof1.sList = newSList1;

        proof2.cList = newCList2;
        proof2.sList = newSList2;

        /* Iterate over the domain */
        for (int i = 0; i < domain.size(); i++) {

            ModInteger y;
            ModInteger z;
            ModInteger d = domain.get(i);

            ModInteger s1 = proof1.sList.get(i);
            ModInteger s2 = proof2.sList.get(i);

            ModInteger c1 = proof1.cList.get(i);
            ModInteger c2 = proof1.cList.get(i);

            /* s' = s1 + s2 */
            sList.add(s1.add(s2));

            /* c' = c1 + c2 */
            cList.add(c1.add(c2));

            /* This will be needed for computing z_i */
            ModInteger negC1 = c1.negate();
            ModInteger negC2 = c2.negate();

            /* This is essentially the message corresponding to domain member d mapped into G */
            ModInteger fpow = g.pow(d);

            /* Compute a group member y = g^s * (g^r)^(-c) = g^(s - r*c) */
            ModInteger y1 = g.pow(s1).multiply(cipherText1.getG().pow(negC1));
             ModInteger y2 = g.pow(s2).multiply(cipherText2.getG().pow(negC2));

            /* Now this is y1*y2 / [g^(r2*c1+r1*c2)] = g^(s'-r'c') = y(s',r',c') = y' */
            y = y1.multiply(y2).divide(g.pow(cipherText2.getR().multiply(c1).add(cipherText1.getR().multiply(c2))));

            /* Compute a cipher, of the form z = g^xs * [(g^rx * f^m)/f^d]^(-c_i) = g^[x(s - rc_i)] * f^[c_i*(d - m)] */
            ModInteger z1 = h.pow(s1).multiply(cipherText1.getH().divide(fpow).pow(negC1));
            ModInteger z2 = h.pow(s2).multiply(cipherText2.getH().divide(fpow).pow(negC2));

            /* Now this is z1*z2 / [f^(m2*c1+m1*c2)] = z1*z2 / [ bigH2^c1 * bigH1^c2 ] = z(y', s',c') = z' */
            z = z1.multiply(z2).divide(cipherText2.getH().pow(c1).multiply(cipherText1.getH().pow(c2)));

            /* If this is true, then this means that d=m */
            if (bigH.divide(fpow).equals(h.pow(cipherText1.getR().add(cipherText2.getR())))) {

                y = g.pow(t);
                z = h.pow(t);
                cList.set(i, ModInteger.ZERO);
                sList.set(i, ModInteger.ZERO);
                indexInDomain = i;
            }

            /* Add our random ciphers and members to their respective lists */
            yList.add(y);
            zList.add(z);

            sb.append(y);
            sb.append(z);
        }

        ModInteger c = new ModInteger(Util.sha1(sb.toString()), publicKey.getQ(), 16).mod(publicKey.getQ());
        ModInteger realC = new ModInteger(c, publicKey.getQ());

        for (ModInteger fakeC : cList) realC = realC.subtract(fakeC);

        /* Note that realC is now c - (sum(cList)) = hash(sb) - sum(cList). If we tack this onto existing cList, then
         * sum(cList) = hash(sb). When this gets verified, then cChoices = sum(cList) = hash(sb) = c
         */

        /* This will ensure that y = g^(s' - r'c') = g^(realC*r'+t - r'*realC) = g^t which is what was committed */
        /* Since z = y^x * f^[c(d-m)] = (g^t)^x f^[realC(d-m)] = h^t when d=m which is what was committed */
        cList.set(indexInDomain, realC);
        sList.set(indexInDomain, realC.multiply(cipherText1.getR().add(cipherText2.getR())).add(t));

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
