package com.opswat;

import java.net.URL;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStreamReader;
import java.io.BufferedReader;
import java.io.DataOutputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.OutputStream;
import org.json.JSONObject;

public class OpswatService {

    private static String host = "https://api.metadefender.com/v4/";
    private static String api_key = "API_KEY"; // Replace with own API Key.
    private static String content_type = "application/octet-stream";

    /**
     * Establish Connection - Set up HTTP URL header and Method Request.
     *
     * @param url_builder - HTTP URL Path
     * @param request_type - HTTP Method Request
     * @return - Settings of HTTP URL Connection
     */
    public static HttpURLConnection establishConnection(String url_builder,
            String method)
            throws FileNotFoundException,
            MalformedURLException, IOException {

        URL url = new URL(url_builder);
        HttpURLConnection url_conn = (HttpURLConnection) url.openConnection();
        url_conn.setRequestMethod(method);
        url_conn.setRequestProperty("apikey", api_key);
        return url_conn;
    }

    /**
     * Hash Lookup - Check if there are previously cached results for the file.
     *
     * @param hash - Hash of provided file used to look up existing scans
     * @return response - Retrieves existing result from scanned file  
     */
    public static String hashLookup(String hash)
            throws FileNotFoundException, MalformedURLException, IOException {

        String url_builder = host + "hash/" + hash;
        HttpURLConnection url_conn = null;

        try {
            url_conn = establishConnection(url_builder, "GET");
            url_conn.connect();

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(url_conn.getInputStream())
            );

            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = br.readLine()) != null) {
                response.append(inputLine);
            }
            br.close();

            return response.toString();
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        }

        return null;
    }

    /**
     * Upload File - Upload file if hash was not found.
     *
     * @param file - Send the file using POST request
     * @return data_id - Retrieve its data_id from scan
     */
    public static String uploadFile(File file) throws IOException {

        String url_builder = host + "file/";
        String resp = "";
        String data_id = "";
        String crlf = "\r\n";
        String doubleHyphens = "--";
        String boundary = "****";
        HttpURLConnection url_conn = null;
        OutputStream os = null;

        try {
            url_conn = establishConnection(url_builder, "POST");
            url_conn.setRequestProperty("content-type", content_type);
            url_conn.setDoOutput(true);
            url_conn.connect();

            os = new DataOutputStream(url_conn.getOutputStream());

            String header = doubleHyphens + boundary + crlf;
            header += "Content-Disposition: "
                    + "form-data;name=\"file\";"
                    + "filename=\"" + file.getName()
                    + "\"" + crlf + crlf;
            os.write(header.getBytes());

            FileInputStream is = new FileInputStream(file);

            byte[] bytes = new byte[4096];
            int length;
            while ((length = is.read()) > -1) {
                os.write(bytes, 0, length);
            }

            os.write(crlf.getBytes());

            String footer = crlf + doubleHyphens + boundary
                    + doubleHyphens + crlf;
            os.write(footer.getBytes());
            os.flush();

            try (BufferedReader br = new BufferedReader(
                    new InputStreamReader(url_conn.getInputStream()))) {

                StringBuilder sb = new StringBuilder();
                for (int c; (c = br.read()) >= 0;) {
                    sb.append((char) c);
                }
                resp = sb.toString();

                JSONObject json_obj = new JSONObject(resp);
                data_id = json_obj.getString("data_id");
                return data_id;
            } catch (IOException e) {
            }

        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        } finally {
            if (null != url_conn) {
                url_conn.disconnect();
            }
        }
        return data_id;
    }

    /**
     * Get Result - Retrieve results of uploaded file.
     *
     * @param data_id - Get scan results using data_id
     * @return response - Retrieves completed scan results from queue.
     */
    public static String getResult(String data_id)
            throws MalformedURLException,
            IOException, InterruptedException {
        String url_builder = host + "file/" + data_id;
        HttpURLConnection url_conn = null;

        try {
            url_conn = establishConnection(url_builder, "GET");
            url_conn.connect();

            BufferedReader br = new BufferedReader(
                    new InputStreamReader(url_conn.getInputStream())
            );

            String inputLine;
            StringBuilder response = new StringBuilder();
            while ((inputLine = br.readLine()) != null) {
                response.append(inputLine);
            }

            br.close();
            asyncQueue(data_id, response.toString());

            return response.toString();
        } catch (FileNotFoundException e) {
        } catch (IOException e) {
        }
        return null;
    }

    /**
     * Asynchronous Queue - Repeatedly call the API until 
     *                      result_scans.progress_percentage
     *                      is equal to 100.
     * @param data_id - Parameter needed to repeatedly call getResult()
     * @param response - Retrieving most updated result of progress_percentage
     */
    public static void asyncQueue(String data_id, String response)
            throws IOException, InterruptedException {
        JSONObject json_obj = new JSONObject(response);
        JSONObject progress = json_obj.getJSONObject("scan_results");

        Thread.sleep(1000);
        if ((progress.getInt("progress_percentage")) != 100) {
            getResult(data_id);
        } else {
            printResult(main.FILE, json_obj);
        }

    }

    /**
     * Print Result - Display information from JSON results.
     *
     * @param file - Name of the samplefile.txt
     * @param res - JSON results from scanned file
     */
    public static void printResult(File file, JSONObject res)
            throws InterruptedException {

        JSONObject result = res.getJSONObject("scan_results");
        JSONObject details = result.getJSONObject("scan_details");
        JSONObject engines;

        System.out.println("filename: " + file.getName());
        System.out.println("overall status: "
                + result.optString("scan_all_result_a") + "\n");

        for (String key : details.keySet()) {

            engines = details.getJSONObject(key);
            System.out.println("engine: " + key);

            if (!engines.getString("threat_found").isEmpty()) {
                System.out.println("threat_found: "
                        + engines.getString("thread_found"));
            } else {
                System.out.println("threat_found: Clean");
            }

            System.out.println("scan_result: "
                    + engines.optString("scan_result_i"));
            System.out.println("def_time: "
                    + engines.optString("def_time") + "\n");
        }
    }
}
