package com.opswat;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import org.json.JSONObject;

public class main {

    public static final File FILE = new File("./samplefile.txt");

    /**
     * Scan File - retrieves result from MetaDefender Cloud API using the hash
     * of samplefile.txt or upload the file and get results using its data_id.
     *
     * @param FILE - File path of testing file samplefile.txt
     */
    private static void scanFile(File FILE)
            throws NoSuchAlgorithmException,
            FileNotFoundException, IOException, InterruptedException {

        String hash_algorithm = "SHA-1"; // MD5, SHA-1, SHA-256
        String hash = "";
        String response = "";
        String data_id = "";
        JSONObject json_obj;

        /* 1. Calculate the hash of the given sameplfile.txt. */
        hash = Hash.generate(FILE, hash_algorithm);

        /* 2. Perform a hash lookup against MetaDefender Cloud API.
              Check if there are previously cached results for the file. */
        response = OpswatService.hashLookup(hash);

        /* 3. If results are found then skip to 6. */
        if (response != null) {
            json_obj = new JSONObject(response);

            /* 6. Display results. */
            OpswatService.printResult(FILE, json_obj);

            /* 4. If no results are found then upload the file, 
                  and return its data_id. */
        } else {
            data_id = OpswatService.uploadFile(FILE);

            /* 5. Repeatedly pull on the data_id to return results. */
            /* 6. Display results. */
            OpswatService.getResult(data_id);

        }
    }

    public static void main(String[] args)
            throws NoSuchAlgorithmException,
            FileNotFoundException, InterruptedException {

        if (FILE.exists()) {
            try {
                scanFile(FILE);
            } catch (IOException e) {
                e.printStackTrace();
            }

        } else {
            System.out.println("File does not exists.");
        }
    }

}
