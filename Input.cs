using System;
using System.Text.Json;
using System.IO;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Text;

namespace ItSec_ver4
{
   public class Input
    {
        public void start(string []arr)
        {
            string secretkeyinp = "";
            string choice = arr[0].ToUpper();
            string clientFile = "";
            string serverFile = "";
            string prop = "";
            
            string masterpassword;
            
            

            switch (choice)
            {
                
                case "INIT":

                    if (arr.Length == 3)
                    {
                        clientFile = arr[1];
                        serverFile = arr[2];
                        Console.WriteLine("Enter masterpassword");
                        masterpassword = Console.ReadLine();
                        Init(clientFile, serverFile, masterpassword);
                    }
                    else
                    {
                        Console.WriteLine("Enter clientfile name and serverfile name");
                    }


                break;
                case "CREATE":

                    if (arr.Length == 3)
                    {
                        clientFile = arr[1];
                        serverFile = arr[2];
                        Console.WriteLine("Enter masterpassword");
                        masterpassword = Console.ReadLine();
                        Console.WriteLine("Enter secretkey");
                        secretkeyinp = Console.ReadLine();

                        Create(clientFile, serverFile, masterpassword, secretkeyinp);
                    }
                    else
                    {
                        Console.WriteLine("Enter clientfile name and serverfile name");
                    }
    
                    break;
                
                case "GET":

                    if (arr.Length == 4 || arr.Length == 3)
                    {
                        clientFile = arr[1];
                        serverFile = arr[2];
                        if (arr.Length == 4)
                        {
                            prop = arr[3];
                        }
                        else
                        {
                            prop = null;
                        }
                        Console.WriteLine("Enter masterpassword");
                        masterpassword = Console.ReadLine();
                        Get(clientFile, serverFile, prop, masterpassword);
                    }
                    else
                    {
                        Console.WriteLine("Enter clientfile name and serverfilename. Prop is optional");
                    }
                    break;

                case "SET":
                    if (arr.Length <= 2)
                    {
                        Console.WriteLine("You have to enter both a clientfile name and serverfile name.");
                    }
                    else if (arr.Length == 3)
                    {
                        Console.WriteLine("You have to enter a property name.");
                    }
                    else if (arr.Length == 5 || arr.Length == 4)
                    {
                        
                            clientFile = arr[1];
                            serverFile = arr[2];
                            prop = arr[3];

                            string gpw;

                            Console.WriteLine("Enter masterpassword");
                            masterpassword = Console.ReadLine();
                            if (arr.Length == 5)
                            {
                                gpw = arr[4];
                            }
                            else
                            {
                                gpw = null;
                            }
                            Set(clientFile, serverFile, prop, gpw, masterpassword);
                        
                    }
                    else
                    {
                        Console.WriteLine("Enter clientfile name, serverfilename and a prop. You can also enter the password for prop");
                    }
                    break;

                case "DELETE":
                    if (arr.Length == 2)
                    {
                        Console.WriteLine("Enter both clientfile name and serverfile name.");
                    }
                    else if (arr.Length == 3)
                    {
                        Console.WriteLine("You have to enter a property name");
                    }
                    else if (arr.Length ==4)
                    {
                        clientFile = arr[1];
                        serverFile = arr[2];
                        prop = arr[3];
                        Console.WriteLine("Enter masterpassword");
                        masterpassword = Console.ReadLine();
                        Delete(clientFile, serverFile, prop, masterpassword);
                    }
                    else
                    {
                        Console.WriteLine("Enter clientfile name, serverfilename and prop");
                    }
                    break;

                case "SECRET":
                    if (arr.Length== 2)
                    {
                        clientFile = arr[1];
                        Secret(clientFile);
                    }
                    else
                    {
                        Console.WriteLine("Enter only the clientfile");
                    }

                    break;


            }
            
        }

        
        public void Init(string clientFile, string serverFile, string masterpwd)
        {
            //generear en IV samt sparar i en sträng
            byte[] iv = Kryptering.GenerateIV();
            string ivstring = Convert.ToBase64String(iv);

            //vaultdict
            Dictionary<string, string> vautlDict = new Dictionary<string, string>();
            string vaultDictString = JsonSerializer.Serialize(vautlDict);

            //generear en sk samt sparar i en sträng
            byte[] secretkey = Kryptering.GenerateSecretKey();
            string secretkeystring = Convert.ToBase64String(secretkey);

            byte[] vaultkey = Kryptering.GenerateVaultKey(masterpwd, secretkey);


            //Krypterar valvet
            byte[] encVault = Kryptering.EncryptStringToBytes_Aes(vaultDictString, vaultkey, iv);
            string encVaultString = Convert.ToBase64String(encVault);

            //Vault
            Dictionary<string, string> vault = new Dictionary<string, string>();
            string jsonVault = JsonSerializer.Serialize(vault);

            //Skapar Clientdict
            Dictionary<string, string> clientDict = new Dictionary<string, string>();
           
            clientDict.Add("Secret key", secretkeystring);



            string clientContent = JsonSerializer.Serialize(clientDict);
           

            Dictionary<string, string> serverDict = new Dictionary<string, string>();
            
            serverDict.Add("Vault", encVaultString);
            serverDict.Add("IV", ivstring);


            string serverContent = JsonSerializer.Serialize(serverDict);

            File.WriteAllText(clientFile, clientContent);
            File.WriteAllText(serverFile, serverContent);

            

            Console.WriteLine(clientContent);

            
        }
        public static void Set(string clientfile, string serverfile, string prop, string generatepw, string pwd)
        {
            try
            {
                // Deserialize the encrypted vault to a dictionary
                Dictionary<string, string> decryptVaultDict =JsonSerializer.Deserialize<Dictionary<string,string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));
                

                // Check if the key already exists in the dictionary
                if (decryptVaultDict.ContainsKey(prop))
                {
                    Console.WriteLine(prop + " is already stored in vault, try again");
                    Environment.Exit(0);
                }

                // Prompt the user for a new password or generate one
                string value;

                if (generatepw == "-g" || generatepw == "--generate")
                {
                    value = Kryptering.PasswordGenerator(20);
                    Console.WriteLine("Your new password is " + value);
                }
                else if (generatepw != null)
                {
                    value = generatepw;
                    
                }
                else
                {
                    Console.WriteLine("Enter new password for " + prop);
                    value = Console.ReadLine();
                   
                }

                //// Add the new key-value pair to the dictionary, excluding "Vault" and "IV"
                
                
                
                decryptVaultDict.Add(prop, value);

                // Serialize the modified dictionary and encrypt it
                
                string encryptedVaultContent = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, pwd);

                // Save the encrypted vault to the serverfile
                Serverwrite(encryptedVaultContent, serverfile);

                Console.WriteLine("Operation performed");
            }
            catch (Exception)
            {
                Console.WriteLine("Wrong password");
            }
        }


        static void Create(string clientFile, string serverFile, string masterpwd, string secretkey)
        {
            try
            {

            Dictionary<string, string> decryptvaultDict = new Dictionary<string, string>();
            //writes the secretkey to the clientfile
            Dictionary<string, string> newClientDict = new Dictionary<string, string>();
            newClientDict.Add("Secret key", secretkey);

            string newClient = JsonSerializer.Serialize(newClientDict);

            File.WriteAllText(clientFile, newClient);

          
                //skapar ny dict, sparar en dekrpyterad, deserialized version 
                
             decryptvaultDict = JsonSerializer.Deserialize<Dictionary<string,string>>(Kryptering.DecryptVault(clientFile, serverFile, masterpwd,secretkey));

           
            string encvaultContent = Kryptering.EncryptVault(decryptvaultDict,clientFile,serverFile,masterpwd,secretkey);

                Serverwrite(encvaultContent, serverFile);

                Console.WriteLine("Operation performed");
            }


            catch (Exception)
            {

                Console.WriteLine("Wrong password or secretkey");
                File.Delete(clientFile);
            }
        }

        static void Get(string clientfile, string serverfile, string prop, string masterpassword)
        {
            Dictionary<string, string> decryptedVaultdict = new Dictionary<string, string>();

            try
            {


                decryptedVaultdict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, masterpassword));


                if (prop != null)
                {
                    if (decryptedVaultdict.ContainsKey(prop))
                    {
                        Console.WriteLine("The password for " + prop + "is: " + decryptedVaultdict[prop]);

                    }
                    else
                    {
                        Console.WriteLine("Prop doesnt exist");
                    }
                }
                else
                {
                    Console.WriteLine("Properties in vault is: ");
                    foreach (var key in decryptedVaultdict.Keys)
                    {
                        Console.WriteLine(key);
                    }
                }
            }
            catch (Exception)
            {
                Console.WriteLine("Wrong password");
            }
           
        }

        static void Delete (string clientfile, string serverfile, string prop, string masterpassword)
        {
            try
            {
                // Deserialize the encrypted vault to a dictionary
                Dictionary<string, string> decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string,string>>(Kryptering.DecryptVault(clientfile, serverfile, masterpassword));
                //Dictionary<string, string> decryptVaultDict = JsonSerializer.Deserialize<Dictionary<string, string>>(Kryptering.DecryptVault(clientfile, serverfile, pwd));

                if (decryptVaultDict.ContainsKey(prop))
                {
                    decryptVaultDict.Remove(prop);
                    
                }
                else
                {
                    Console.WriteLine("property not found");
                    Environment.Exit(0);
                }

                // Serialize the modified dictionary and encrypt it
                string vaultContent = JsonSerializer.Serialize(decryptVaultDict);
                string encryptedVaultContent = Kryptering.EncryptVault(decryptVaultDict, clientfile, serverfile, masterpassword);

                // Save the encrypted vault to the serverfile
                Serverwrite(encryptedVaultContent, serverfile);

                Console.WriteLine(prop + " deletion performed");
            }
            catch (Exception)
            {
                Console.WriteLine("Wrong password");
            }

        }

        static void Secret (string clientfile)
        {
            try
            {


                Dictionary<string, string> clientDict = JsonSerializer.Deserialize<Dictionary<string, string>>(File.ReadAllText(clientfile));


                Console.WriteLine("Your secret key is: " + clientDict["Secret key"]);
            }
            catch (Exception)
            {
                Console.WriteLine("Clientfile not found");
            }
        }

       

       

        public static void Serverwrite(string encryptedvault, string serverfile)
        {
            string serverdictstring = File.ReadAllText(serverfile);
            var serverdict = JsonSerializer.Deserialize<Dictionary<string, string>>(serverdictstring);

            if (serverdict.ContainsKey("Vault"))
            {
                serverdict["Vault"] = encryptedvault;
            }
            else
            {
                Console.WriteLine("Vault did not get saved succesfully");
            }

            string newServerDictString = JsonSerializer.Serialize(serverdict);

            File.WriteAllText(serverfile, newServerDictString);

           
        }
    }
}
