package PA01.Cryptography;

import java.math.BigInteger;
import java.util.HashSet;

/**
 * Used to do the decryption of an Affine_Cipher file.
 *
 * @author Ryan Thornton
 * @version 02/07/2023
 */
public class Decryption {
    private final Affine affine;
    private byte[] fully_decrypted;

    /**
     * Constructor of decryption.
     *
     * @param affine current instance of affine
     */
    Decryption(Affine affine) {
        this.affine = affine;
        fully_decrypted = null;
    }

    /**
     * Holds the decryption algo. **Formula** - D = (a^-1(m - b) mod 128).
     *
     * @return byte[] of decrypted bytes
     */
    public byte[] decryption_algo() {
        // to make sure fully_decrypted is not populated
        fully_decrypted = new byte[affine.getAscII_values().length];
        // gets the inverse of "a" from the BigInteger class method of modInverse
        int a_inverse = affine.getKeyPair().a.modInverse(new BigInteger(String.valueOf(affine.MOD_128))).intValue();
        int i = 0;
        for (byte cur : affine.getAscII_values()) {
            // The algo used is inverse from what the encryption method was doing, but I end up getting a negative
            // number mod 128 if not using the conversion to an unsigned long.  The unsigned value allows our number to
            // be strictly positive 0 - 255 instead of -127 - 128.  Anyhow, if I did not use the trick of using
            // unsigned.  Then to counteract the negative number, I add 128 back to the final value.  However, I would
            // still have to handle an edge case, which is when I obtain zero, and I do not add back the 128.  This
            // would always get me back to a positive number of mod 128 and the correct decrypted bytes.
            fully_decrypted[i++] = (byte) (Integer.toUnsignedLong((a_inverse *
                    (cur - affine.getKeyPair().b.intValue()))) % 128);
        }
        return fully_decrypted;
    }

    /***
     * Holds the method for brute forcing a key set.
     * <p>This is the ugliest code I've written in a while, forgive me.</p>
     */
    public void decryption_brute_force_key() {
        // Ultimately this will generate the best key
        int legible_words;
        int max_legible_words = 0;
        KeyPair bestPair = new KeyPair(null, null);
        HashSet<String> curBinaryStringRep;
        for (int i = 0; i < affine.MOD_128; i++) {
            // Checks if the value of "i" is relatively prime to 128
            if (new BigInteger("" + i).gcd(new BigInteger("" + affine.MOD_128)).intValue() == 1) {
                // gets the inverse of "i" mod 128 from the BigInteger class method of modInverse
                for (int j = 0; j < affine.MOD_128; j++) {
                    legible_words = 0;
                    // updates big integers each iteration
                    affine.getKeyPair().setKeyPair(new BigInteger("" + i), new BigInteger("" + j));
                    // updates the decryption each iteration
                    fully_decrypted = decryption_algo();
                    // updates the strings of bits to compare
                    curBinaryStringRep = affine.create_binary_lines(fully_decrypted);
                    // compares both current string representation of binary to library
                    for (String cur : curBinaryStringRep) {
                        if (affine.getDictionary_values().contains(cur)) {
                            legible_words++;
                        }
                    }
                    // If the words found is greater than max already
                    if (legible_words > max_legible_words) {
                        max_legible_words = legible_words;
                        bestPair = new KeyPair(new BigInteger("" + i), new BigInteger("" + j));
                    }
                }
            }
        }
        // Sets final best key pair to affine's key pair
        affine.getKeyPair().setKeyPair(bestPair.a, bestPair.b);
        System.out.printf("Key set found contains A = %d and B = %d.\n", bestPair.a, bestPair.b);
        System.out.println(max_legible_words + " words were found to be legible with this key set.");
        System.out.println("Please review your output file for the full decipher.");
    }
}


