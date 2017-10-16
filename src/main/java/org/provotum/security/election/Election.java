package org.provotum.security.election;

import org.provotum.security.SearchSpaceExhaustedException;
import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.arithmetic.Polynomial;
import org.provotum.security.elgamal.threshold.CipherText;
import org.provotum.security.elgamal.PublicKey;
import org.provotum.security.vote.Vote;

import java.util.ArrayList;
import java.util.List;

public class Election {

    private PublicKey publicKey;
    private List<Vote> votes = new ArrayList<>();

    public Election(PublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public void castVote(Vote vote) {
        this.votes.add(vote);
    }

    public Vote sumVotes() {
        Vote total = new Vote(new CipherText(
                this.publicKey.getP(),
                this.publicKey.getG(),
                this.publicKey.getY()
        ));

        for (Vote vote : this.votes) {
            total = vote.multiply(total);
        }

        return total;
    }

    public ModInteger getFinalSum(List<ModInteger> partialDecryptedSums, List<ModInteger> coefficients, Vote summedVotes, PublicKey publicKey) {
        Polynomial polynomial = new Polynomial(
                publicKey.getP(),
                publicKey.getQ(),
                publicKey.getG(),
                coefficients
        );

        List<ModInteger> lagrangeCoeffs = polynomial.getLagrangeCoefficients();
        int lsize = lagrangeCoeffs.size();

        ModInteger pli = new ModInteger(ModInteger.ONE, publicKey.getP());

        for (int j = 0; j < lsize; j++) {
            ModInteger psi = partialDecryptedSums.get(j);
            ModInteger lci = lagrangeCoeffs.get(0);
            ModInteger product = psi.pow(lci).multiply(pli);

            pli = product;
        }

        ModInteger bigH = summedVotes.getCipherText().getH();
        ModInteger target = bigH.divide(pli);
        ModInteger j = null;
        boolean gotResult = false;

        int numVotes = votes.size();

        System.out.println("Looping " + (numVotes + 1) + " times to look for result");

        for (int k = 0; k <= numVotes; k++) {
            j = new ModInteger(k, publicKey.getQ());

            System.out.println("DOES " + j + " equal " + target + "?");

            // TODO: maybe j mod p
            if (j.equals(target)) {
                System.out.println("GOT RESULT!!!");
                gotResult = true;
                break;
            }
        }


        if (gotResult) {
            System.out.println("Adding result: " + j);
            return j;
        } else {
            System.out.println("THROWING EXCEPTION!!!");
            throw new SearchSpaceExhaustedException("Error searching for " + target);
        }
    }
}
