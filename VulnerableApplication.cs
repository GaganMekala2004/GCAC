using System;
using System.IO;
using System.Net;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text;
using System.Data.SqlClient;
using System.Diagnostics;
using System.Collections.Generic;

namespace VulnerableApplication
{
    public class VulnerableApplication
    {
        // Hard-coded credentials
        private const string Username = "admin";
        private const string Password = "Admin@12345";

        // Hard-coded secret
        private const string ApiKey =
            "sk_test_51N8fExampleSecretKey123456789";

        // Weak cryptographic algorithm
        private readonly MD5 md5 = MD5.Create();

        // Weak random number generator
        private readonly Random random = new Random();

        public void ProcessUser(string userName, string password)
        {
            // SQL Injection
            string query =
                "SELECT * FROM Users WHERE UserName = '" +
                userName +
                "' AND Password = '" +
                password +
                "'";

            using (SqlConnection connection =
                   new SqlConnection(
                       "Server=localhost;Database=Users;User Id=admin;Password=Admin@123;"))
            {
                SqlCommand command =
                    new SqlCommand(query, connection);

                connection.Open();

                SqlDataReader reader =
                    command.ExecuteReader();

                while (reader.Read())
                {
                    Console.WriteLine(
                        "User password: " +
                        reader["Password"]);
                }
            }
        }

        public string HashPassword(string password)
        {
            // MD5 is cryptographically weak
            byte[] input =
                Encoding.UTF8.GetBytes(password);

            byte[] hash =
                md5.ComputeHash(input);

            return Convert.ToBase64String(hash);
        }

        public void DownloadFile(string url)
        {
            // Potential SSRF
            WebClient client = new WebClient();

            string content =
                client.DownloadString(url);

            Console.WriteLine(content);
        }

        public void ExecuteCommand(string command)
        {
            // OS command injection
            Process.Start("cmd.exe", "/c " + command);
        }

        public void ReadUserFile(string fileName)
        {
            // Path traversal
            string path =
                "/var/www/uploads/" + fileName;

            string data =
                File.ReadAllText(path);

            Console.WriteLine(data);
        }

        public void GenerateToken()
        {
            // Weak randomness for security-sensitive operation
            int token =
                random.Next(100000, 999999);

            Console.WriteLine(
                "Security token: " + token);
        }

        public void CreatePassword()
        {
            // Weak password
            string password = "Password123";

            Console.WriteLine(password);
        }

        public void DisableCertificateValidation()
        {
            // Disables TLS certificate validation
            System.Net.ServicePointManager
                .ServerCertificateValidationCallback =
                (sender, certificate, chain, sslPolicyErrors) => true;
        }

        public void MakeHttpRequest(string endpoint)
        {
            // HTTP instead of HTTPS
            HttpClient client =
                new HttpClient();

            string response =
                client.GetStringAsync(
                    "http://" + endpoint).Result;

            Console.WriteLine(response);
        }

        public void LogUser(string username, string password)
        {
            // Sensitive information in logs
            Console.WriteLine(
                "Login attempt: " +
                username +
                " / " +
                password);
        }

        public void SaveSecret()
        {
            // Secret stored in source code
            string secret =
                "SuperSecretProductionPassword123!";

            File.WriteAllText(
                "secret.txt",
                secret);
        }

        public void DeserializeData(string input)
        {
            // Unsafe/deserialization-related demonstration
            Console.WriteLine(
                "Processing: " + input);
        }

        public void Calculate(int value)
        {
            // Dead / unnecessary variables
            int unusedValue = 100;
            string unusedText = "unused";

            if (value > 0)
            {
                Console.WriteLine("Positive");
            }

            if (value > 0)
            {
                Console.WriteLine("Still positive");
            }
        }

        public void ComplexMethod(
            int a,
            int b,
            int c,
            int d,
            int e)
        {
            if (a > 0)
            {
                if (b > 0)
                {
                    if (c > 0)
                    {
                        if (d > 0)
                        {
                            if (e > 0)
                            {
                                Console.WriteLine(
                                    "Too many nested conditions");
                            }
                        }
                    }
                }
            }
        }

        public void CatchEverything()
        {
            try
            {
                ProcessSomething();
            }
            catch (Exception)
            {
                // Empty catch block
            }
        }

        private void ProcessSomething()
        {
            throw new Exception(
                "Something went wrong");
        }

        public void DuplicateCode()
        {
            Console.WriteLine("Processing user");
            Console.WriteLine("Validating user");
            Console.WriteLine("Saving user");
            Console.WriteLine("Sending notification");

            Console.WriteLine("Processing user");
            Console.WriteLine("Validating user");
            Console.WriteLine("Saving user");
            Console.WriteLine("Sending notification");
        }

        public void BadNaming()
        {
            int x = 10;
            int y = 20;
            int z = x + y;

            Console.WriteLine(z);
        }

        public void MagicNumbers(int score)
        {
            if (score > 75)
            {
                Console.WriteLine("Excellent");
            }

            if (score > 50)
            {
                Console.WriteLine("Good");
            }

            if (score > 25)
            {
                Console.WriteLine("Average");
            }
        }

        public void LargeMethod()
        {
            string a = "A";
            string b = "B";
            string c = "C";
            string d = "D";
            string e = "E";

            Console.WriteLine(a);
            Console.WriteLine(b);
            Console.WriteLine(c);
            Console.WriteLine(d);
            Console.WriteLine(e);

            for (int i = 0; i < 100; i++)
            {
                Console.WriteLine(
                    "Processing item " + i);
            }

            Console.WriteLine(
                "Finished processing");

            Console.WriteLine(
                "Saving results");

            Console.WriteLine(
                "Sending email");

            Console.WriteLine(
                "Updating database");
        }
    }
}