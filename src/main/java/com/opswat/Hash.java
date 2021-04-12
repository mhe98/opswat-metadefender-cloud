package com.opswat;

import java.io.File;
import java.io.BufferedInputStream;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.security.NoSuchAlgorithmException;
import java.security.MessageDigest;

public class Hash {

    /**
     * Generate - Calculates the hash in byte array of a given file 
     *            using a hashing algorithm.
     * 
     * @param file - Calculate hash of samplefile.txt
     * @param hash_algorithm - MD5: 16 byte | SHA-1: 20 byte | SHA-256: 32 byte
     * @return convertByteArrayToHexString(hash) - Raw hash digest
     */
    public static String generate(File file, String hash_algorithm) 
            throws NoSuchAlgorithmException, 
            UnsupportedEncodingException, 
            FileNotFoundException, IOException {
        
        int bufferSize = 8192; // 8 KB
        byte[] buffer = new byte[bufferSize];
        int count;
        MessageDigest md = MessageDigest.getInstance(hash_algorithm);
        BufferedInputStream bis = 
                new BufferedInputStream(new FileInputStream(file));
        
        while ((count = bis.read(buffer)) > 0) {
            md.update(buffer, 0, count);
        }
        bis.close();

        byte[] hash = md.digest();

        return convertByteArrayToHexString(hash);
    }
    
    /**
     * Convert Byte Array to Hex String - Converts generated hash to a String.
     * 
     * @param array_bytes - Generated raw hash digest
     * @return sb.toString() - String of the converted byte array
     */
    public static String convertByteArrayToHexString(byte[] array_bytes) {
        
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < array_bytes.length; i++) {
            sb.append(Integer.toString((array_bytes[i] & 0xff) + 0x100, 16)
                    .substring(1));
        }
        
        return sb.toString();
    }

}
