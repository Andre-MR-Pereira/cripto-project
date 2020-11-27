# Homomorphic Encryption Lab

Get an overview of the Microsoft SEAL encryption library and how to use it.

## Introduction

In this lab we will see how to encrypt fitness activity messages between a client and a server. We'll use a console app as the client to send encrypted messages to an API.

### A) What is SEAL?

[Microsoft SEAL](https://www.microsoft.com/en-us/research/project/microsoft-seal/) is a low-level cryptographic library providing an API for encryption, computing on encrypted data, and decryption, using a special encryption technology called homomorphic encryption. Microsoft SEAL is written in C++17 and has no external dependencies. It comes with complete .NET Standard wrappers and multiple thoroughly commented examples. This lab is based on the Fitness Tracker, an app that tracks the user's running data and uses the SEAL library to encrypt it, send it up to the server and send back the results of calculations encrypted for the client to decrypt. The cloud service never decrypts the data.

### B) Download the lab materials

Follow the next steps to download the sample code provided for this lab. It includes a Console app and an API that we will use to implement a simple Client/Server interaction using encryption.

1. Click **Clone or download** from this repo.
1. You can clone the repo using git or click **Download ZIP** to directly download the code from your browser.

   > **Alert:** Make sure to uncompress/clone your code into **Downloads/encryption-lab**.

1. We will use Visual Studio 2019 for development. If you don't have Visual Studio you can download it from the URL given below.
    * Download Visual Studio 2019 (any edition) from [https://www.visualstudio.com/downloads/](https://www.visualstudio.com/downloads/).
    * Refer Visual Studio 2019 system requirement from [https://docs.microsoft.com/en-us/visualstudio/releases/2019/system-requirements](https://docs.microsoft.com/en-us/visualstudio/releases/2019/system-requirements).

### C) Build the Microsoft SEAL library (Optional)

The following steps are optional since the **DLL** files are already provided in the sample code. Use the next steps in case you need to update to a different version of the library or if you want to learn more about the process.

    > **Note:** The *DLLs** provided with the source code were built for **Windows x64**, if you want to use the library in a different platform check the instructions from the **SEAL** repo and build your own version.

1. Clone the project from https://github.com/microsoft/SEAL
1. Open **Visual Studio** from the Start Menu.
1. Click **Open Project/Solution**.
1. Open the *SEAL.sln* solution from the cloned folder.
1. Change the configuration from **Debug** to **Release**.
1. Follow the instructions under the [Building and Using Microsoft SEAL for .NET](https://github.com/microsoft/SEAL#building-and-using-microsoft-seal-for-net).
1. After you run the instructions, two *.dll* files should have been generated: *sealnetnative.dll* and *SEALNet.dll*.

    > **Note:** The folders in which those files were generated are specified in the repo instructions. The folder for *SEALNet.dll* file is `dotnet\lib\$(Configuration)\netstandard2.0`. And the folder for the *sealnetnative.dll* file is `dotnet\lib\$(Platform)\$(Configuration)`.

### D) See the unencrypted app in action

In this section we will setup our local environment and run the provided unencrypted app.

1. Open **Visual Studio** from the Start Menu.
1. Click **Open Project/Solution**.
1. Open the `FitnessTracker.sln` solution from the previously downloaded code.
1. Right click the **FitnessTracker** solution in the Solution Explorer.
1. Click on **Rebuild Solution**.

    > **Note:** This process might take a few minutes but you can continue with the next steps while it finishes.

1. Review the 3 projects that are part of the solution:

    * **FitnessTrackerAPI:** .NET Core API with endpoints to post metrics, perform calculations and retrieve the keys needed for encryption/decryption.
    * **FitnessTrackerClient:** Console Application that sends requests to the API to store run metrics and return a summary of the metrics that have been sent.
    * **FitnessTracker.Common** .NET Core library project that holds some useful model definitions and a utility class to be shared within the other two projects.

1. Follow the next steps to setup your Solution and run both the **API** and the **Console App** from the same Visual Studio instance:
    * Right click the **FitnessTracker** solution.
    * Click on **Set StartUp Projects...**.
    * Select the `Multiple startup projects` option.
    * Set the `Start` Action for both **FitnessTrackerAPI** and **FitnessTrackerClient**.
    * Click **Ok** to save your changes.

1. Click on the **Start** button from Visual Studio and wait for the app to run.

    > **Note:** This might take a few minutes as it will start both the Console App and the API. A new web page will be opened in your browser, wait for it to load.

1. Once that the app is running use the **Command Window** that was opened. This is the *Console App* that we will use for testing.

    > **Note:** Look for the Console App in your Windows toolbar if you can't see it.

1. Type `1`  and press **Enter** to send a new record to the API.
1. Provide the requested information:
    * Running distance (km): `10`.
    * Running time (hours): `2`.

    > **Note:** If you check the Output console, you'll see some useful prints of what is being sent to the API from the CLIENT.

1. Type `2`  and press **Enter** to retrieve the running statistics from the API.

    > **Note:** The response from the API is a `SummaryItem` containing 3 properties: TotalRuns, TotalDistance and TotalHours. In this case the data is **unencrypted** in a base 64 value.

    > **Note:** Also, you should see in the Ouput console, some useful debug prints on what's being sent and received between the API and the CLIENT.

1. Provide more running metrics and notice that the API is aggregating the data when we request for the metrics summary.


## Add encryption/decryption to your App

Here we will add the encryption/decryption capabilities to our projects.

### A) Add the SEAL library to your Projects

In this section we will do the initial review of the projects included in the solution and add the SEAL library.

1. Right click on the **FitnessTrackerClient** project and go to **Add > Reference**.
1. Click on the **Browse** button and look for the `SEALNet.dll` file provided at the `Downloads/encryption-lab/Resources` folder or from the folder where you built the library.
1. Right click on the project again, and click on **Open Folder in File Explorer**.
    
    > **Note:** This should open a **File Explorer** window with your project's location in your machine.

1. Copy the file `Downloads/encryption-lab/Resources/sealnetnative.dll` to the `bin\Debug\netcoreapp2.2` folder opened in the last step.
1. Repeat the last steps to add the library to the **FitnessTrackerAPI** project.
1. Right click the **FitnessTracker** solution and select **Rebuild Solution**.

### B) Setup encryption (public / secret key)

First step is to set the private and public keys in both projects by completing the following steps:

1. In the **FitnessTracker.Common** project, open the `Utils/SEALUtils.cs` file.
1. Find the `GetContext` method at the end of the file and replace the content with the following code snippet:
    ```cs
    var encryptionParameters = new EncryptionParameters(SchemeType.BFV)
    {
        PolyModulusDegree = 32768,
        CoeffModulus = DefaultParams.CoeffModulus128(polyModulusDegree: 32768)
    };

    encryptionParameters.SetPlainModulus(0x133Ful);

    Debug.WriteLine("[COMMON]: Successfully created context");

    return SEALContext.Create(encryptionParameters);
    ```

    > **Note:** This code initializes the encryption parameters. Once an instance of [EncryptionParameters](https://github.com/microsoft/SEAL/blob/master/dotnet/src/EncryptionParameters.cs) is populated with appropriate parameters, it can be used to create an instance of the **SEALContext**. This method will be used by both projects to create the **SealContext**. 

1. In the **FitnessTrackerAPI** project, open the `MetricsController.cs` file.
1. Add the following import at the beginning of the file:

```cs
using Microsoft.Research.SEAL;
```

1. Look for the variable `private List<double> _times = new List<double>();` and add the following code snippet after it:

    ```cs
    private readonly SEALContext _sealContext;

    private readonly KeyGenerator _keyGenerator;
    private Evaluator _evaluator;
    private Encryptor _encryptor;
    ```

    > **Note:** This will include the variables required to generate the keys and work with *encryption/decription*. We'll use the *Evaluator* and *Encryptor* later on in the lab, for now we'll focus on the **KeyGenerator**.

1. Find the `// Initialize context` comment in the constructor method and replace it with the following code snippet:

    ```cs
    // Getting context from Commons project
    _sealContext = SEALUtils.GetContext();
    ```

1. Find the `// Initialize key generator and encryptor` comment in the same method and replace it with the following code snippet:

    ```cs
    // Initialize key Generator that will be use to get the Public and Secret keys
    _keyGenerator = new KeyGenerator(_sealContext);

    // Initializing encryptor
    _encryptor = new Encryptor(_sealContext, _keyGenerator.PublicKey);
    ```

    >**Note:** The key generator object will have the secret and public keys that will be used to encrypt and decrypt the data. These keys must be shared by the Server and the Client to be able to encrypt/decrypt the information correctly. We will use an API endpoint to get these keys in the client.


1. Find the `GetKeys()` method, and replace the content with the following code snippet:

    ```cs
    Debug.WriteLine("[API]: GetKeys - return SEAL public and secret keys to client");
    return new KeysModel
    {
        PublicKey = SEALUtils.PublicKeyToBase64String(_keyGenerator.PublicKey),
        SecretKey = SEALUtils.SecretKeyToBase64String(_keyGenerator.SecretKey)
    };
    ```

    > **Note:** This method basically generates an object containing the Public Key and Secret Key as base64 strings using the key generator that was created earlier. We'll be using **base64 encoding** to handle the data as it is easier to **Load** and **Save** the encrypted values later on.

1. **Save** your changes.
1. Go to **FitnessTrackerClient** project and open the `Program.cs` file.
1. Modify the following lines:

    * Add the following import at the beginning of the file:

    ```cs
    using Microsoft.Research.SEAL;
    ```

    * Add the following variables to the beginning of the class:

    ```cs
    private static Encryptor _encryptor;
    private static Decryptor _decryptor;
    private static SEALContext _context;
    ```

    * Replace the `// Add Initialization code here` comment with the following code snippet:

    ```cs
    _context = SEALUtils.GetContext();
    ```

1. Now, in the same file, look for the `// Add keys code here` comment, and replace it with the following code snippet:

    ```cs
    var keys = await FitnessTrackerClient.GetKeys();

    // Create encryptor

    // Create decryptor
    ```

    > **Note:** Here we call an endpoint in the **FitnessTrackerAPI** to get the Public and Secret keys. If you want to encrypt data in one side (client or server), and decrypt it in the other side you'll need to use the same keys, otherwise you'll get different results.


### C) Encrypting API requests

In this section we will see how to send encrypted data to our API.

1. Make sure you have the `FitnessTrackerClient\Program.cs` file open.
1. First we need to initialize the encryptor. Look for the `// Create encryptor` comment and replace it with the following code snippet:

    ```cs
    var publicKey = SEALUtils.BuildPublicKeyFromBase64String(keys.PublicKey, _context);
    _encryptor = new Encryptor(_context, publicKey);
    ```
    > **Note:** We will use the public key that we received from the API to initialize the encryptor.

1. Find the `// Encrypt distance` comment in the `SendNewRun` method and add the following code snippet:

    ```cs
    // We will convert the Int value to Hexadecimal using the ToString("X") method
    var plaintext = new Plaintext($"{newRunningDistance.ToString("X")}");
    var ciphertextDistance = new Ciphertext();
    _encryptor.Encrypt(plaintext, ciphertextDistance);
    ```

    > **Note:** We will convert the value provided by the user to Hexadecimal because that's how is use by our evaluator in the server, and finally encrypt the value to a cipher to be send in the request as base 64.

1. Find the following line below the code previously added:

    ```cs
    var base64Distance = SEALUtils.Base64Encode(newRunningDistance.ToString());
    ```

    And replace it with

    ```cs
    var base64Distance = SEALUtils.CiphertextToBase64String(ciphertextDistance);
    ```

1. Find the `// Encrypt time` comment in the same method and add the following code snippet to get the new run time:

    ```cs
    // We will convert the Int value to Hexadecimal using the ToString("X") method
    var plaintextTime = new Plaintext($"{newRunningTime.ToString("X")}");
    var ciphertextTime = new Ciphertext();
    _encryptor.Encrypt(plaintextTime, ciphertextTime);
    ```

    > **Note:** Here we will do the same but for the time of the run.

1. Find the following line below the code previously added:

    ```cs
    var base64Time = SEALUtils.Base64Encode(newRunningTime.ToString());
    ```
    
    And replace it with

    ```cs
    var base64Time = SEALUtils.CiphertextToBase64String(ciphertextTime);
    ```

    > **Note:** Now that we have the distance and time values encrypted we make the API requests using the encrypted data. Later on we'll see how the server can perform calculations without actually decrypting these values.

### D) Decrypt Summary Statistics in the Client

In this section we will see how to decrypt the data from the API response to display it to the user.

1. Make sure you are in the `FitnessTrackerClient\Program.cs` file.
1. First we need to initialize the decryptor. Look for the `// Create decryptor` comment and replace it with the following code snippet:

    ```cs
    var secretKey = SEALUtils.BuildSecretKeyFromBase64String(keys.SecretKey, _context);
    _decryptor = new Decryptor(_context, secretKey);
    ```

    > **Note:** We will use the secret key that we get from the API to initialize the decryptor.

1. Go to the `GetMetrics` method.
1. Find the `// Decrypt the data` comment and add the following code snippet after it:

    ```cs
    var ciphertextTotalRuns = SEALUtils.BuildCiphertextFromBase64String(metrics.TotalRuns, _context);
    var plaintextTotalRuns = new Plaintext();
    _decryptor.Decrypt(ciphertextTotalRuns, plaintextTotalRuns);

    var ciphertextTotalDistance = SEALUtils.BuildCiphertextFromBase64String(metrics.TotalDistance, _context);
    var plaintextTotalDistance = new Plaintext();
    _decryptor.Decrypt(ciphertextTotalDistance, plaintextTotalDistance);

    var ciphertextTotalHours = SEALUtils.BuildCiphertextFromBase64String(metrics.TotalHours, _context);
    var plaintextTotalHours = new Plaintext();
    _decryptor.Decrypt(ciphertextTotalHours, plaintextTotalHours);
    ```

    > **Note:** For all the 3 metrics we will build a new **Ciphertext** object using the *base64* encrypted data. Then, we'll create a new **Plaintext** object to store the decryption result.

1. Find the `// Print metrics in console` comment  and **replace** the next line with the following code snippet:

    ```cs
    PrintMetrics(plaintextTotalRuns.ToString(), plaintextTotalDistance.ToString(), plaintextTotalHours.ToString());
    ```

    > **Note:** Since we already have the decrypted data now we are just calling the `PrintMetrics` with this data to show it to the user.


## Perform summary statistics on the encrypted data

Now that we are sending encrypted data we will see how to use this data in the API without decrypting the values and test it to see the encryption in action.

### A) Using encrypted data for calculations

Here we will see how to use a basic **add** method to aggregate the metrics in the API without actually decrypting the information.

1. Open the `Controllers/MetricsController.cs` file in the **FitnessTrackerAPI** project.

1. Add the following code snippet after the variable `private Encryptor _encryptor`:

    ```cs
    // Store running metrics in memory. Use a long term storage for production scenarios.
    private List<ClientData> _metrics = new List<ClientData>();
    ```

1. Find the `// Initialize evaluator` comment in the constructor method and replace it with the following line of code:

    ```cs
    // Initialize evaluator to be use on calculations with context
    _evaluator = new Evaluator(_sealContext);
    ```

    >**Note:** The evaluator is the one in charge of doing all the calculations with the encrypted data. We don't have to use decryption in order to run mathematical functions using the SEAL library.

1. Find the `AddRunItem` method, and replace the method content with the following code snippet:

    ```cs
            LogUtils.RunItemInfo("API", "AddRunItem", request);
            var distance = SEALUtils.BuildCiphertextFromBase64String(request.Distance, _sealContext);
            var time = SEALUtils.BuildCiphertextFromBase64String(request.Time, _sealContext);

            _metrics.Add(new ClientData
            {
                Distance = distance,
                Hours = time
            });

            return Ok();
    ```

    > **Note:** The code takes the metrics in *base64* and stores them in memory as a [Cyphertext](https://github.com/microsoft/SEAL/blob/master/dotnet/src/Ciphertext.cs). It also prints in the Output console, the received request's contents.

1. Add the following method at the end of the class:

    ```cs
    private Ciphertext SumEncryptedValues(IEnumerable<Ciphertext> encryptedData)
    {
        if (encryptedData.Any())
        {
            Ciphertext encTotal = new Ciphertext();
            _evaluator.AddMany(encryptedData, encTotal);
            return encTotal;
        }
        else
        {
            return SEALUtils.CreateCiphertextFromInt(0, _encryptor);
        }
    }
    ```
    > **Note:** The **AddMany** method is receiving the destination object where the calculation result will be stored.

1. Find the `GetMetrics` method, and replace its contents with the following code snippet:

    ```cs
        var totalDistance = SumEncryptedValues(_metrics.Select(m => m.Distance));
        var totalHours = SumEncryptedValues(_metrics.Select(m => m.Hours));
        var totalMetrics = SEALUtils.CreateCiphertextFromInt(_metrics.Count(), _encryptor);
        
        var summaryItem = new SummaryItem
        {
            TotalRuns = SEALUtils.CiphertextToBase64String(totalMetrics),
            TotalDistance = SEALUtils.CiphertextToBase64String(totalDistance),
            TotalHours = SEALUtils.CiphertextToBase64String(totalHours)
        };
        
        LogUtils.SummaryStatisticInfo("API", "GetMetrics", summaryItem);
        
        return Ok(summaryItem);
    ```

    > **Note:** This code uses the method that we previously added to perform the calculations on the metrics stored in memory. It also prints the *summaryItem*'s contents in the Output console.
 
### B) Test the encryption capabilities

We will use the Client to send and receive requests to the API and see encryption in action.

1. Click on the **Start** button from Visual Studio and wait for the app to run.
1. Open the **Console App** and wait for the menu to display.

    > **Note:** This might take a few minutes as it takes some time to initialize the **SEALContext**.

1. Type `1`  and press **Enter** to send a new record to the API.
1. Provide the requested information:
    * Running distance (km): `10`.
    * Running time (hours): `2`.
1. Type `1` and press **Enter** to send another record to the API.
1. Provide the requested information:
    * Running distance (km): `5`.
    * Running time (hours): `1`.
1. Type `2`  and press **Enter** to retrieve the running statistics from the API.
1. The results displayed are the calculations performed by the API. Review that the numbers match the expected result.

*Media Elements and Templates. You may copy and use images, clip art, animations, sounds, music, shapes, video clips and templates provided with the sample application and identified for such use in documents and projects that you create using the sample application. These use rights only apply to your use of the sample application and you may not redistribute such media otherwise.*
