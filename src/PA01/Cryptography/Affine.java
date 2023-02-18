package PA01.Cryptography;

import java.io.*;
import java.math.BigInteger;
import java.util.ArrayList;

/**
 * This file is used for PA: PA01.Cryptography.Cryptography for CS327.
 *
 * <p>
 * ***IMPORTANT*** - To run this in the command line using JAVA: Needs to be in SRC folder and command line params need
 * to be "java PA01.Cryptography.Affine -commands-"
 * ***Very Important*** - For myself, param a has to be within 1-128 and c0prime with 128.  Also, b can be any arbitrary
 * number.
 * </p>
 *
 * @author Ryan Thornton
 * @version 02/07/2023
 */
public class Affine {

    public final int MOD_128 = 128;
    public final int EN_DE_ARG_LENGTH = 5;
    public final int CIPHER_ARG_LENGTH = 4;
    public final int A_INDEX = 3;
    public final int B_INDEX = 4;
    public final int TYPE_INDEX = 0;
    public final int INPUT_INDEX = 1;
    public final int OUTPUT_INDEX = 2;
    public final int DICTIONARY_INDEX = 3;
    private KeyPair key_pair;
    private byte[] ascII_values;
    private ArrayList<String> dictionary_values;
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
            if (args[affine.TYPE_INDEX].equals("encrypt") && args.length == affine.EN_DE_ARG_LENGTH) {
                affine.handles_args(args, affine);
                // creates encryption object and handles the encryption
                Encryption encryption = new Encryption(affine);
                byte[] fully_encrypted = encryption.encryption_algo();
                // writes fully encrypted bytes to file
                affine.out.write(fully_encrypted);
                // Handles decrypt command
            } else if (args[affine.TYPE_INDEX].equals("decrypt") && args.length == affine.EN_DE_ARG_LENGTH) {
                affine.handles_args(args, affine);
                // creates decryption object and handles the decryption
                Decryption decryption = new Decryption(affine);
                byte[] fully_decrypted = decryption.decryption_algo();
                // writes fully decrypted bytes to file
                affine.out.write(fully_decrypted);
                // Handles decipher command
            } else if (args[affine.TYPE_INDEX].equals("decipher") && args.length == affine.CIPHER_ARG_LENGTH) {
                affine.handles_args(args, affine);
                // creates decryption object, handles the brute forcing of a key pair, and decryption of file
                Decryption decryption = new Decryption(affine);
                decryption.decryption_brute_force_key();
                byte[] fully_decrypted = decryption.decryption_algo();
                // writes fully decrypted bytes to file
                affine.out.write(fully_decrypted);
            } else {
                throw new Exception();
            }
            affine.out.close();
        } catch (Exception e) {
            if (e.getClass().equals(IllegalArgumentException.class)) {
                System.err.println(affine.key_pair.a.intValue() + " is not co-prime with 128");
            } else {
                affine.err();
            }
        }
    }

    /**
     * Parses everything that entails each valid command line argument.
     *
     * @param args   command lines args
     * @param affine instance of affine
     * @throws Exception if parseInt fails or the files are bad or "a" is not co-prime with 128
     */
    private void handles_args(String[] args, Affine affine) throws Exception {
        File input_file = new File(args[affine.INPUT_INDEX]);
        File output_file = new File(args[affine.OUTPUT_INDEX]);
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(input_file));
        out = new BufferedOutputStream((new FileOutputStream(output_file)));
        // Reads all bytes from input file into byte array
        affine.ascII_values = in.readAllBytes();
        in.close();
        // If mode is not decipher it creates a key pair and check for relatively prime with "a" to 128
        if (!args[0].equals("decipher")) {
            key_pair = new KeyPair(new BigInteger(args[affine.A_INDEX]).abs(),
                    new BigInteger(args[affine.B_INDEX]).abs());
            // Checks to see if a value is within limits of mod 128
            if (key_pair.a.gcd(new BigInteger("128")).intValue() != 1) {
                throw new IllegalArgumentException();
            }
            // If mode is decipher it creates a blank key pair and saves the dictionary file as a Byte[] array
        } else {
            key_pair = new KeyPair(null, null);
            File dictionary_file = new File(args[affine.DICTIONARY_INDEX]);
            BufferedInputStream dict_in = new BufferedInputStream(new FileInputStream(dictionary_file));
            // Reads all bytes from dictionary file and converts from byte[] to strings for future processing
            dictionary_values = create_binary_lines(dict_in.readAllBytes(), 0);
            dict_in.close();
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
     * Gets a key pair.
     *
     * @return KeyPair
     */
    public KeyPair getKeyPair() {
        return this.key_pair;
    }

    /**
     * Gets ASCII values.
     *
     * @return byte[] ascII_values
     */
    public byte[] getAscII_values() {
        return this.ascII_values;
    }

    /**
     * Gets dictionary values.
     *
     * @return byte[] dictionary_values
     */
    public ArrayList<String> getDictionary_values() {
        return this.dictionary_values;
    }

    /**
     * The purpose of this method is to take a files byte data and create a byte string representing a line within a
     * text file.
     *
     * @param bytes to use
     * @return ArrayList to return
     */
    public ArrayList<String> create_binary_lines(byte[] bytes, int includeNewLineChar) {
        // Reads all bytes from bytes and converts from byte[] to strings for future processing
        StringBuilder curBytesOfWord = new StringBuilder();
        ArrayList<String> string_of_bytes = new ArrayList<>();
        for (byte cur : bytes) {
            // values 10 and 13 in ASCII are treated as new line characters
            if (cur == 10 || cur == 13) {
                // Includes or doesn't include new line char
                if (includeNewLineChar == 1) {
                    curBytesOfWord.append(cur);
                }
                string_of_bytes.add(curBytesOfWord.toString());
                curBytesOfWord = new StringBuilder();
            } else {
                curBytesOfWord.append(cur);
            }
        }
        return string_of_bytes;
    }
}
