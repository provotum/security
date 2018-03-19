Provotum Security
===================

**Credits**: The encryption and proof logic is heavily inspired by the [Adder Voting System](https://github.com/FreeAndFair/evoting-systems/tree/master/EVTs/adder).

# Requirements
* Java 8
* Maven
* Install the Java Cryptography Extension available at [http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html](http://www.oracle.com/technetwork/java/javase/downloads/jce8-download-2133166.html)
* Put them into the appropriate directory (overwrite if already existing) as described at [https://stackoverflow.com/questions/37741142/how-to-install-unlimited-strength-jce-for-java-8-in-os-x](https://stackoverflow.com/questions/37741142/how-to-install-unlimited-strength-jce-for-java-8-in-os-x). You may get an exception `Caused by: java.security.InvalidKeyException: Illegal key size or default parameters` otherwise.

# Installation

* Clone this repo and cd into it: `git clone git@github.com:provotum/security.git && cd security`
* Run `mvn clean install` to install the application and run the corresponding tests

# Development

## Main Interfaces
* `IHomomorphicEncryption` This interface ensures the signature for all implementations of a particular kind of homomorphic encryption. As a generic parameter, it requires the kind of ciphertext it operates on.
* `IHomomorphicCipherText` Homomorphic cipher texts allow to operate on each other, abstracting the concrete mathematical details from the caller. It requires a concrete ciphertext as generic parameter.
* `IMembershipProof` The interface for a membership proof requires a class implementing \texttt{IHomomorphicCiphertext} as generic parameter, restricting the classes it is able to generate proofs for.

## Main Implementations
* [`ElGamal additive Ciphertext`](https://github.com/provotum/security/blob/master/src/main/java/org/provotum/security/elgamal/additive/CipherText.java): An exponential ElGamal homomorphic ciphertext in the form of
```
    E(m) = (g^r, h^r * g^m), with
    
    g = generator
    m = message</li>
    h = g^x i.e. the public key whereas x = private key
    r = [0, q-1]
    
    which operates in an additive manner over the encrypted plaintexts:
    
    E(m1) * E(m2) = (g^(r1+r2), h^(r1+r2) * g^(m1+m2))
                  = E(m1 + m2)
```
* [`ElGamal Encryption`](https://github.com/provotum/security/blob/master/src/main/java/org/provotum/security/elgamal/additive/Encryption.java) The encryption and decryption component for the above documented ciphertext.
* [`Non-interactive Membership Proof`](https://github.com/provotum/security/blob/master/src/main/java/org/provotum/security/elgamal/proof/noninteractive/MembershipProof.java) The non-interactive membership proof allowing to prove that a certain ElGamal ciphertext actually contains a particular cleartext value.
