package PA01.Cryptography;

import java.math.BigInteger;

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
     * Holds the decryption algo. **Formula** - D = (a^-1(m - b) mod 128) + 128.
     */
    public byte[] decryptionAlgo() {
        // to make sure fully_decrypted is not populated
        fully_decrypted = new byte[affine.getAscII_values().length];
        // gets the inverse of "a" from the BigInteger class method of modInverse
        int a_inverse = affine.getA().modInverse(new BigInteger(String.valueOf(affine.MOD_128))).intValue();
        System.out.println(a_inverse);
        int i = 0;
        for (byte cur : affine.getAscII_values()) {
            // This algo used is inverse from what encryption method is doing, but we end up getting a negative number
            // mod 128.  So, to counteract the negative number, I add 128 back to the final value.  This always gets me
            // back to a positive number of mod 128 and the correct decrypted bytes.  After testing, this was the
            // correct solution to my problem.
            fully_decrypted[i++] = (byte) (((a_inverse * (cur - affine.getB().intValue())) % affine.MOD_128) + 128);
        }
        return fully_decrypted;
    }
}
