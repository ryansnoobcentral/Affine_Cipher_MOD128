package PA01.Cryptography;

import java.math.BigInteger;

/**
 * This class represents a key pair for encryption/decryption.
 *
 * @author Ryan Thornton
 * @version 02/16/2023
 */
public class KeyPair {

    public BigInteger a;
    public BigInteger b;

    /**
     * Main constructor of key pair.
     *
     * @param a relatively prime # to 128
     * @param b # between 0 - 127
     */
    KeyPair(BigInteger a, BigInteger b) {
        setKeyPair(a, b);
    }

    /**
     * Sets the key pair.
     *
     * @param a relatively prime # to 128
     * @param b # between 0 - 127
     */
    public void setKeyPair(BigInteger a, BigInteger b) {
        this.a = a;
        this.b = b;
    }
}
