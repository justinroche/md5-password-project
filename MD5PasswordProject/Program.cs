using System.Security.Cryptography;
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
      byte[] stolenHash = StringTo16BitHash(stolenHashString);

      // Compute MD5 hash of password
      string password = "password1";
      byte[] passwordAttemptHashBytes = GetMD5Hash(password);
      string passwordAttemptHashString = HashToString(passwordAttemptHashBytes);
      TryLogin(password, stolenHash);

      // Generate possible passwords from set of keywords.
      // Check for correct formatting.
      // Hash valid passwords and check against stolen hash.
      // Print and store incorrect passwords and hashes to txt file.
      // Confirm valid password and hash and break from algorithm.

    }

    static byte[] GetMD5Hash(string password)
    {
      byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
      byte[] hashBytes = MD5.HashData(passwordBytes);
      return hashBytes;
    }

    static string HashToString(byte[] md5Hash)
    {
      string computedHashString = md5Hash != null ? BitConverter.ToString(md5Hash).Replace("-", "") : string.Empty;
      return computedHashString;
    }

    static byte[] StringTo16BitHash(string hashString)
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

    static bool TryLogin(string password, byte[] stolenHashString)
    {
      byte[] passwordAttemptHash = GetMD5Hash(password);
      string passwordAttemptHashString = HashToString(passwordAttemptHash);

      Console.Write(password + " --> " + passwordAttemptHashString);
      bool result = CompareHashes(passwordAttemptHash, stolenHashString);

      if (!result)
        return false;

      Console.WriteLine("Hashes match! Password: " + password);
      Console.WriteLine(passwordAttemptHashString + " = " + stolenHashString);
      return true;
    }

  }

}