package org.provotum.security.elgamal.proof.noninteractive;

import org.provotum.security.Util;
import org.provotum.security.api.IMembershipProof;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.elgamal.additive.CipherText;

import java.util.List;

/**
 * A proof that an ElGamal encrypted value is within a particular range.
 */
public class MembershipProof implements IMembershipProof {

    private List<ModInteger> sList;
    private List<ModInteger> cList;
    private List<ModInteger> yList;
    private List<ModInteger> zList;

    private ModInteger p;
    private ModInteger q;


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


    /**
     * Create a string representation of this proof.
     *
     * @return The string representation of this proof.
     */
    public String toString() {
        StringBuilder sb = new StringBuilder(8192);

        sb.append("p");
        sb.append(p);

        for (ModInteger y : yList) {
            sb.append("y");
            sb.append(y.finalized());
        }

        for (ModInteger z : zList) {
            sb.append("z");
            sb.append(z.finalized());
        }

        for (ModInteger s : sList) {
            sb.append("s");
            sb.append(s.finalized());
        }

        for (ModInteger c1 : cList) {
            sb.append("c");
            sb.append(c1.finalized());
        }

        return sb.toString();
    }

    @Override
    public int hashCode() {
        return this.toString().hashCode();
    }

    @Override
    public boolean equals(Object obj) {
        return obj instanceof MembershipProof && this.toString().equals(obj.toString());
    }
}
