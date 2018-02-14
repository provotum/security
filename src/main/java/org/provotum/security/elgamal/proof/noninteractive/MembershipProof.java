package org.provotum.security.elgamal.proof.noninteractive;

import org.provotum.security.Util;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;

import java.util.ArrayList;
import java.util.List;

public class MembershipProof {

    private PublicKey publicKey;

    private List<ModInteger> sList = new ArrayList<>();
    private List<ModInteger> cList = new ArrayList<>();
    private List<ModInteger> yList = new ArrayList<>();
    private List<ModInteger> zList = new ArrayList<>();

    private String origCHash;
    private StringBuilder origSb;

    public MembershipProof(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void commit(ModInteger message, ModInteger bigG, ModInteger bigH, ModInteger random) {
        /* Get p and q from the key */
        ModInteger p = this.publicKey.getP();
        ModInteger q = this.publicKey.getQ();

        ModInteger g = new ModInteger(this.publicKey.getG(), p);
        ModInteger h = new ModInteger(this.publicKey.getH(), p);

        /* bigG (g^r), bigH (g^(rx) * f^m), and r */

        /* Generate a random value t */
        ModInteger t = ModInteger.random(q);

        /*
         * Create a StringBuffer for holding information to create a commitment string
         *
         *  Note that this string will be of the form:
         *       (g, g^x, g^r, (g^(rx) * f^m), y_0, z_0, ..., y_n, z_n)
         */
        StringBuilder sb = new StringBuilder(4096);

        /* Append all the numbers to the string*/
        sb.append(g);
        sb.append(h);
        sb.append(bigG);
        sb.append(bigH);

        /* Initialize our domain counter */
        int indexInDomain = 0;

        // messages can be either 0 or one.
        List<ModInteger> domain = new ArrayList<>();
        domain.add(ModInteger.ZERO);
        domain.add(ModInteger.ONE);


        /* Iterate over the domain */
        for (int i = 0; i < domain.size(); i++) {

            ModInteger y;
            ModInteger z;
            ModInteger d = domain.get(i);

            /* See if the value is this particular member of the domain */
            if (d.equals(message)) {

                /* If it is, fill c_i and s_i with dummy values for now */
                this.sList.add(ModInteger.ZERO);
                this.cList.add(ModInteger.ZERO);

                /* Compute random group member */
                y = g.pow(t);

                /* commit a random cipher, as part of the commitment process */
                z = h.pow(t);

                /* Record the index of the valid value */
                indexInDomain = i;
            } else {

                /* If we don't have a valid value, generate random numbers for c_i and s_i */
                this.sList.add(ModInteger.random(q));
                this.cList.add(ModInteger.random(q));
                ModInteger s = this.sList.get(i);
                ModInteger c = this.cList.get(i);

                /* This will be needed for computing z_i */
                ModInteger negC = c.negate();

                /* This is essentially the message corresponding to domain member d mapped into G */
                ModInteger fpow = g.pow(d);

                /* Compute a group member g^s * (g^r)^(-c_i) = g^(s - r*c_i) */
                y = g.pow(s).multiply(bigG.pow(negC));

                /* Compute a cipher, of the form g^xs * [(g^rx * f^m)/f^d]^(-c_i) = g^[x(s - rc_i)] * f^[c_i*(d - m)] */
                z = h.pow(s).multiply(bigH.divide(fpow).pow(negC));
            }

            /* Add our random ciphers and members to their respective lists */
            yList.add(y);
            zList.add(z);

            /* Add them to the commitment string */
            sb.append(y);
            sb.append(z);
        }

        /* Hash the commitment string */
        this.origSb = sb;
        String s = sb.toString();
        String cHash = Util.sha1(s);
        this.origCHash = cHash;

        /* From the hash, construct a numerical value */
        ModInteger c1 = new ModInteger(cHash, q, 16).mod(q);
        ModInteger realC = new ModInteger(c1, q);

        /* Now subtract all of the generated fake commits off the hash value (note, the valid value will still be 0 here) */
        for (ModInteger fakeC : cList) {
            realC = realC.subtract(fakeC);
        }

        /* Note that realC (call it p) is now c1 - (sum(cList)) */

        /* Compute pr + t using our real commitment value and add it in the right place */
        sList.set(indexInDomain, realC.multiply(random).add(t));

        /* Add our real commitment value into the commit list in the right place */
        cList.set(indexInDomain, realC);
    }

    public boolean verify(CipherText cipherText, List<ModInteger> domain) {
        if (domain.size() < this.cList.size() ||
            domain.size() < this.sList.size()) {
            // The domain of the message is bigger than specified.
            // Therefore, the proof that the message is within the given domain is invalid.
            return false;
        }

        /* Extract necessary key components for computation */
        ModInteger p = this.publicKey.getP();
        ModInteger q = this.publicKey.getQ();
        ModInteger g = new ModInteger(this.publicKey.getG(), p);
        ModInteger h = new ModInteger(this.publicKey.getH(), p);

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

}
