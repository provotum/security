package org.provotum.security.elgamal.proof;

import org.provotum.security.Util;
import org.provotum.security.api.IMembershipProofFactory;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.proof.noninteractive.MembershipProof;

import java.util.ArrayList;
import java.util.List;
import java.util.NoSuchElementException;
import java.util.StringTokenizer;

/**
 * Creates a proof that an additive ElGamal ciphertext is within a particular domain.
 */
public class AdditiveElGamalMembershipProofFactory implements IMembershipProofFactory<MembershipProof> {

    /**
     * {@inheritDoc}
     */
    @Override
    public MembershipProof createProof(ModInteger p, ModInteger q, ModInteger g, ModInteger h, ModInteger message, ModInteger bigG, ModInteger bigH, ModInteger random) {
        List<ModInteger> sList = new ArrayList<>();
        List<ModInteger> cList = new ArrayList<>();
        List<ModInteger> yList = new ArrayList<>();
        List<ModInteger> zList = new ArrayList<>();

        /* Get p and q from the key */

        g = new ModInteger(g, p);
        h = new ModInteger(h, p);

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
                sList.add(ModInteger.random(q));
                cList.add(ModInteger.random(q));
                ModInteger s = sList.get(i);
                ModInteger c = cList.get(i);

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
        String s = sb.toString();
        String cHash = Util.sha1(s);

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

        return new MembershipProof(p, q, yList, zList, sList, cList);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public MembershipProof fromString(String s) {
        StringTokenizer st = new StringTokenizer(s, "pyzsc", true);
        int numTokens = st.countTokens() - 2;

        if ((numTokens % 8) != 0) {
            throw new IllegalArgumentException("number of tokens not divisible by 8");
        }

        int count = numTokens / 8;

        try {
            if (! st.nextToken().equals("p")) {
                throw new IllegalArgumentException("expected token: 'p'");
            }

            ModInteger p = new ModInteger(st.nextToken());
            ModInteger q = p.subtract(ModInteger.ONE).divide(ModInteger.TWO);

            List<ModInteger> yList = new ArrayList<>(count);

            for (int ySize = 0; ySize < count; ySize++) {
                if (! st.nextToken().equals("y")) {
                    throw new IllegalArgumentException("expected token: 'y'");
                }

                yList.add(new ModInteger(st.nextToken(), p));
            }

            List<ModInteger> zList = new ArrayList<>(count);

            for (int zSize = 0; zSize < count; zSize++) {
                if (! st.nextToken().equals("z")) {
                    throw new IllegalArgumentException("expected token: 'z'");
                }

                zList.add(new ModInteger(st.nextToken(), p));
            }

            List<ModInteger> sList = new ArrayList<>(count);

            for (int sSize = 0; sSize < count; sSize++) {
                if (! st.nextToken().equals("s")) {
                    throw new IllegalArgumentException("expected token: 's'");
                }

                sList.add(new ModInteger(st.nextToken(), q));
            }

            List<ModInteger> cList = new ArrayList<>(count);

            for (int cSize = 0; cSize < count; cSize++) {
                if (! st.nextToken().equals("c")) {
                    throw new IllegalArgumentException("expected token: 'c'");
                }

                String t = st.nextToken();

                cList.add(new ModInteger(t, q));
            }

            return new MembershipProof(p, q, yList, zList, sList, cList);
        } catch (NoSuchElementException | NumberFormatException nsee) {
            throw new IllegalArgumentException(nsee.getMessage());
        }
    }
}
