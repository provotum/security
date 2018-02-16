package org.provotum.security.serializer;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.proof.noninteractive.MembershipProof;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;
import java.util.StringTokenizer;

public class MembershipProofSerializer {

    private static final int RADIX = 36;

    public static String serialize(MembershipProof proof) {
        StringBuilder sb = new StringBuilder(8192);

        sb.append("P");
        sb.append(proof.getP().finalized().toString(MembershipProofSerializer.RADIX));

        for (ModInteger y : proof.getyList()) {
            sb.append("Y");
            sb.append(y.finalized().toString(MembershipProofSerializer.RADIX));
        }

        for (ModInteger z : proof.getzList()) {
            sb.append("Z");
            sb.append(z.finalized().toString(MembershipProofSerializer.RADIX));
        }

        for (ModInteger s : proof.getsList()) {
            sb.append("S");
            sb.append(s.finalized().toString(MembershipProofSerializer.RADIX));
        }

        for (ModInteger c1 : proof.getcList()) {
            sb.append("C");
            sb.append(c1.finalized().toString(MembershipProofSerializer.RADIX));
        }

        return sb.toString();
    }

    public static MembershipProof fromString(String proof) {
        StringTokenizer st = new StringTokenizer(proof, "PYZSC", true);

        if (! st.nextToken().equals("P")) {
            throw new IllegalArgumentException("expected token: 'p'");
        }

        ModInteger p = new ModInteger(new BigInteger(st.nextToken(), MembershipProofSerializer.RADIX));
        ModInteger q = p.subtract(ModInteger.ONE).divide(ModInteger.TWO);

        List<ModInteger> yList = new ArrayList<>();
        List<ModInteger> zList = new ArrayList<>();
        List<ModInteger> sList = new ArrayList<>();
        List<ModInteger> cList = new ArrayList<>();

        while (st.hasMoreTokens()) {
            String delimiter = st.nextToken();
            String value = st.nextToken();

            switch (delimiter) {
                case "Y":
                    yList.add(new ModInteger(new BigInteger(value, MembershipProofSerializer.RADIX).toString(), p));
                    break;
                case "Z":
                    zList.add(new ModInteger(new BigInteger(value, MembershipProofSerializer.RADIX).toString(), p));
                    break;
                case "S":
                    sList.add(new ModInteger(new BigInteger(value, MembershipProofSerializer.RADIX).toString(), q));
                    break;
                case "C":
                    cList.add(new ModInteger(new BigInteger(value, MembershipProofSerializer.RADIX).toString(), q));
                    break;
                default:
                    throw new IllegalArgumentException("Invalid token " + value);
            }
        }

        return new MembershipProof(p, q, yList, zList, sList, cList);
    }
}
