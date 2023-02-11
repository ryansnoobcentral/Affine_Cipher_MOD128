package PA01.Cryptography;

import java.io.*;
import java.math.BigInteger;

/**
 * This file is used for PA: PA01.Cryptography.Cryptography for CS327.
 *
 * <p>
 * ***IMPORTANT*** - To run this in the command line using JAVA: Needs to be in SRC folder and command line params need
 * to be "java PA01.Cryptography.Affine -commands-"
 * </p>
 *
 * @author Ryan Thornton
 * @version 02/07/2023
 */
public class Affine {

    public final int MOD_128 = 128;
    private BigInteger a;
    private BigInteger b;
    private byte[] ascII_values;
    private File dictionary_file;

    private BufferedInputStream in;
    private BufferedOutputStream out;

    /**
     * Default constructor of affine.
     */
    Affine() {
        // Just to create the object of Affine to use global vars
    }

    /**
     * This main method handles input files and commands
     *
     * @param args args to process.
     */
    public static void main(String[] args) {
        Affine affine = new Affine();

        // If command line is empty
        if (args.length == 0) {
            affine.err();
            return;
        }
        try {
            // Handles encrypt command
            if (args[0].equals("encrypt") && args.length == 5) {
                affine.handles_encrypt_decrypt(args, affine);
                // creates encryption object and handles the encryption
                Encryption encryption = new Encryption(affine);
                byte[] fully_encrypted = encryption.encryptionAlgo();
                // writes fully encrypted bytes to file
                affine.out.write(fully_encrypted);
            } else if (args[0].equals("decrypt") && args.length == 5) {
                affine.handles_encrypt_decrypt(args, affine);
                // creates decryption object and handles the decryption
                Decryption decryption = new Decryption(affine);
                byte[] fully_decrypted = decryption.decryptionAlgo();
                // writes fully decrypted bytes to file
                affine.out.write(fully_decrypted);
            } else if (args[0].equals("decipher") && args.length == 4) {

            } else {
                affine.err();
                return;
            }
            affine.out.close();
        } catch (Exception e) {
            if (e.getClass().equals(IllegalArgumentException.class)) {
                System.err.println(affine.a.intValue() + " is not co-prime with 128");
            } else {
                affine.err();
            }
        }
    }

    /**
     * Parses encrypt and decrypt command line args.
     *
     * @param args   command lines args
     * @param affine instance of affine
     * @throws Exception if parseInt fails or the files are bad or "a" is not co-prime with 128
     */
    private void handles_encrypt_decrypt(String[] args, Affine affine) throws Exception {
        File input_file = new File(args[1]);
        File output_file = new File(args[2]);
        a = new BigInteger(args[3]).abs();
        b = new BigInteger(args[4]).abs();
        in = new BufferedInputStream(new FileInputStream(input_file));
        out = new BufferedOutputStream((new FileOutputStream(output_file)));
        // Reads all bytes from input file into byte array
        affine.ascII_values = affine.in.readAllBytes();
        affine.in.close();
        // Checks to see if a value is within limits of mod 128
        if (a.gcd(new BigInteger("128")).intValue() != 1) {
            throw new IllegalArgumentException();
        }
    }

    /**
     * Prints err statement for failed program runs.
     */
    private void err() {
        System.err.println("""
                Invalid arguments, please check your commands.
                Example Commands: "encrypt [plaintext-file] [output-file] [a] [b]"
                                  "decrypt [ciphertext-file] [output-file] [a] [b]"
                                  "decipher [ciphertext-file] [output-file] [dictionary-file]"
                """);
    }

    /**
     * Gets a value.
     *
     * @return BigInteger a
     */
    public BigInteger getA() {
        return a;
    }

    /**
     * Gets b value.
     *
     * @return BigInteger b
     */
    public BigInteger getB() {
        return b;
    }

    /**
     * Gets ASCII values.
     *
     * @return byte[] ascII_values
     */
    public byte[] getAscII_values() {
        return ascII_values;
    }
}
