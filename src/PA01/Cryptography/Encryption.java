package PA01.Cryptography;

/**
 * Used to do the encryption of an Affine_Cipher file.
 *
 * @author Ryan Thornton
 * @version 02/07/2023
 */
public class Encryption {
    private final Affine affine;
    private byte[] fully_encrypted;

    /**
     * Constructor of encryption.
     *
     * @param affine current instance of affine
     */
    Encryption(Affine affine) {
        this.affine = affine;
        fully_encrypted = null;
    }

    /**
     * Holds the encryption algo. **Formula** - E = (a · m + b) mod 128.
     *
     * @return byte[] of encrypted bytes
     */
    public byte[] encryption_algo() {
        // to make sure fully_encrypted is not populated
        fully_encrypted = new byte[affine.getAscII_values().length];
        // encryption process
        int i = 0;
        for (byte cur : affine.getAscII_values()) {
            fully_encrypted[i++] = (byte) ((affine.getKeyPair().a.intValue() * cur + affine.getKeyPair().b.intValue())
                    % affine.MOD_128);
        }
        return fully_encrypted;
    }
}
