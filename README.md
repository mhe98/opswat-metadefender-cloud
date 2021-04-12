# OPSWAT - MetaDefender Cloud

## Installation Guide:
* Clone repository using Git: 
   ```
    git clone https://github.com/mhe98/opswat-metadefender-cloud.git
   ```
* Clone repository from Visual Studio 2017:
   
   `View > Team Explorer > Local Git Repositories > Click "Clone" tab > Repository location: "https://github.com/mhe98/opswat-metadefender-cloud.git" > Click "Clone"`

## Configuration:

### API Key

Within `OpswatService.java`, overwrite `API_KEY` with your own API Key:

    private static String api_key = "API_KEY"; // Replace with own API Key.

### Input File:

Within `main.java`, provide the file path of your intended file scan: 

    public static final File FILE = new File("Repalce with own samplefile.");


## Problem Description:
Generate a simple program to scan a file against our [metadefender.opswat.com](metadefender.opswat.com) API. OPSWAT online help contains details of our publicly available API along with sample code that shows how to scan a file. However, it is costly to multi-scan a file so we would like you to implement a hash lookup prior to deciding to upload a file, either way you should retrieve results and display them. Please read through the documentation and sample code found at [https://onlinehelp.opswat.com/mdcloud/2._Public_APIs.html](https://onlinehelp.opswat.com/mdcloud/2._Public_APIs.html) to perform the following logic.

  1. Calculate the hash of the given samplefile.txt 
  
  2. Perform a hash lookup against metadefender.opswat.com and see if their are previously cached results for the file
  
  3. If results found then skip to 6
  
  4. If results not found then upload the file, receive a data_id
  
  5. Repeatedly pull on the data_id to retrieve results
  
  6. Display results in format below. You should also have some basic error handling for common HTTP results, but its not necessary to account for every idiosyncrasy of our API. You can show any errors to the standard error and exit the application.
  


   ### Sample Input Command:
    
    upload_file samplefile.txt
    
   ### Sample Output Command:

    filename: samplefile.txt    
    overall_status: Clean
    engine: Ahnlab    
    thread_found: SomeBadMalwareWeFound    
    scan_result: 1
    def_time: 2017-12-05T13:54:00.000Z
    engine: Cyren
    thread_found: Clean
    scan_result: 0
    def_time: 2017-12-05T17:43:00.000Z
    <repeats for each engine>
    END

    
### What you will need/helpful hints
1. You will need to register for a free account at [portal.opswat](portal.opswat.com).com. This will create an account and generate a trial apikey for metadefender.opswat.com. The apikey should be displayed on the "Home" tab once you login to your portal account. Please note this apikey has rate limiting which you may encounter, this is normal.

2.  All of the API descriptions can be found under [https://onlinehelp.opswat.com/mdcloud/3._Public_APIs.html](https://onlinehelp.opswat.com/mdcloud/3._Public_APIs.html) pay particular attention to the following
    
  - [https://onlinehelp.opswat.com/mdcloud/API_Authentication_Mechanisms.html](https://onlinehelp.opswat.com/mdcloud/API_Authentication_Mechanisms.html)
  - [https://onlinehelp.opswat.com/mdcloud/1.1_Scanning_a_file_by_file_upload.html](https://onlinehelp.opswat.com/mdcloud/1.1_Scanning_a_file_by_file_upload.html)
  - [https://onlinehelp.opswat.com/mdcloud/1.2_Retrieving_scan_reports_using_data_ID.html](https://onlinehelp.opswat.com/mdcloud/1.2_Retrieving_scan_reports_using_data_ID.html)
  - [https://onlinehelp.opswat.com/mdcloud/2.1_Retrieving_scan_reports_using_a_data_hash.html](https://onlinehelp.opswat.com/mdcloud/2.1_Retrieving_scan_reports_using_a_data_hash.html)
### What we are looking to see:

1. Smart component choices, we don't expect you to write a JSON parser or reinvent a HTTP client.

2. Clean and well documented code. Any language choice is fine but should be something easily installed and evaluated.

3. A publicly available GIT repo that should contain all your code minus your apikey, we will be providing our own key when we test it out ourselves.

4. A cleanly written and descriptive README that instructs us how to build and execute your project. We will be testing your project on a clean Ubuntu 18.04+ VM or Visual Studio 2017 Windows machine. You can use whatever language or 3rd party library you want, but it should build and execute out of the box on the VM, so test accordingly.
