package org.provotum.security.api;

import org.provotum.security.arithmetic.ModInteger;
import org.provotum.security.elgamal.PrivateKey;
import org.provotum.security.elgamal.PublicKey;

import java.util.List;

/**
 * Encrypt and decrypt a plaintext value in a homomorphic fashion.
 *
 * @param <C> The type of the ciphertext to encrypt a plaintext value to.
 */
public interface IHomomorphicEncryption<C extends IHomomorphicCipherText<C>> {

    /**
     * Encrypt the given message with the given public key.
     *
     * @param publicKey The public key to use for encryption.
     * @param message   The message to encrypt.
     * @return The encrypted cipher text.
     */
    C encrypt(PublicKey publicKey, ModInteger message);

    /**
     * Decrypt the given cipher text with the given private key.
     *
     * @param privateKey The private key used for decryption.
     * @param cipherText The cipher text to decrypt.
     * @return The decrypted value.
     */
    ModInteger decrypt(PrivateKey privateKey, C cipherText);
}
