﻿using System.Security.Cryptography;
using System.Text;

namespace MD5PasswordProject
{

  class Program
  {

    static void Main(string[] args)
    {

      // Get keywords from txt file.
      string[] keywords = File.ReadAllLines("keywords.txt");

      // Get stolen hash
      string stolenHashString = "7b0ca5c95a9398a2f32613d987428180";
      byte[] stolenHash = StringTo16ByteHash(stolenHashString);

      // Compute MD5 hash of password
      string password = "password1";
      TryLogin(password, stolenHash);

      // Generate possible passwords from set of keywords.
      // Check for correct formatting.
      // Confirm valid password and hash and break from algorithm.

    }

    // Compute MD5 hash of password
    static byte[] GetMD5Hash(string password)
    {
      byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
      byte[] hashBytes = MD5.HashData(passwordBytes);
      return hashBytes;
    }

    // Convert 16-byte hash to 32-character hash string
    static string HashToString(byte[] md5Hash)
    {
      string computedHashString = md5Hash != null ? BitConverter.ToString(md5Hash).Replace("-", "") : string.Empty;
      return computedHashString;
    }

    // Convert 32-character hash string to 16-byte hash
    static byte[] StringTo16ByteHash(string hashString)
    {
      if (hashString.Length != 32)
        throw new ArgumentException("Invalid hash string.");

      byte[] hashBytes = new byte[16];
      for (int i = 0; i < 16; i++)
        hashBytes[i] = Convert.ToByte(hashString.Substring(2 * i, 2), 16);
      return hashBytes;
    }

    // Check if hash byte arrays are equal
    static bool CompareHashes(byte[] passwordAttemptHash, byte[] stolenHash)
    {
      for (int i = 0; i < 16; i++)
        if (passwordAttemptHash[i] != stolenHash[i])
          return false;

      return true;
    }

    // Check if password attempt is valid and print result to console and password_attempts.txt
    static bool TryLogin(string passwordAttemptString, byte[] stolenHashString)
    {
      byte[] passwordAttemptHash = GetMD5Hash(passwordAttemptString);
      string passwordAttemptHashString = HashToString(passwordAttemptHash);

      bool result = CompareHashes(passwordAttemptHash, stolenHashString);
      string passwordAttemptResult = passwordAttemptString + " --> " + passwordAttemptHashString;

      Console.WriteLine(passwordAttemptResult);
      File.AppendAllText("password_attempts.txt", passwordAttemptResult + Environment.NewLine);

      if (!result)
        return false;

      Console.WriteLine("Hashes match! Password: " + passwordAttemptString);
      Console.WriteLine(passwordAttemptHashString + " = " + stolenHashString);
      return true;
    }

  }

}