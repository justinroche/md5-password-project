using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace MD5PasswordProject
{

  class Program
  {

    // Get passwords already attempted
    public static string passwordAttemptsPath = "password_attempts_1.txt";
    public static string[] passwordAttempts = File.ReadAllLines(passwordAttemptsPath);

    // Get set of keywords
    public static string keywordsPath = "keywords.txt";
    public static string[] keywords = File.ReadAllLines(keywordsPath);

    static void Main(string[] args)
    {

      // Get stolen hash
      string stolenHashString = "7b0ca5c95a9398a2f32613d987428180";
      byte[] stolenHash = StringTo16ByteHash(stolenHashString);

      Console.WriteLine("Running password generation algorithm...");

      foreach (string keyword in keywords)
      {
        // Generate possible passwords from set of keywords.


        // Check for correct formatting.
        if (!ValidateTarget1String(keyword))
          continue;

        // Check if this password has already been attempted.
        if (PasswordAlreadyAttempted(keyword, passwordAttempts))
          continue;

        // Confirm valid password and hash and break from algorithm.
        if (TryLogin(keyword, stolenHash))
          break;
      }

      Console.WriteLine("Loop completed.");

    }

    static void GeneratePasswords()
    {
      string[] keywordsFormatted = FormatKeywords();

      foreach (string keyword in keywordsFormatted)
      {
        Console.WriteLine(keyword);
      }
    }

    // Format keywords to include lowercase, uppercase, and first-letter capitalized versions
    static string[] FormatKeywords()
    {
      List<string> formattedKeywords = new List<string>();
      foreach (string keyword in keywords)
      {
        if (Regex.IsMatch(keyword, "[a-zA-Z]"))
        {
          formattedKeywords.Add(char.ToUpper(keyword[0]) + keyword[1..]);
          formattedKeywords.Add(keyword.ToUpper());
        }
        formattedKeywords.Add(keyword);
      }
      return formattedKeywords.ToArray();
    }

    // Check if password hash has already been attempted
    static bool PasswordAlreadyAttempted(string passwordAttemptString, string[] passwordAttempts)
    {
      foreach (string attempt in passwordAttempts)
      {
        string password = attempt.Split(' ')[0];
        if (password.Length > 0 && password.Equals(passwordAttemptString))
          return true;
      }
      return false;
    }

    // Validate format of password
    static bool ValidateTarget1String(string input)
    {
      // Check if the string length is between 5 and 10 characters (inclusive)
      if (input.Length < 5 || input.Length > 10)
        return false;

      // Use regular expression to match alphanumeric characters only
      Regex regex = new Regex("^[a-zA-Z0-9]*$");
      return regex.IsMatch(input);
    }

    // Return MD5 hash of password as byte array
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

    // Check if password attempt is valid and print result to console and password attempts file
    static bool TryLogin(string passwordAttemptString, byte[] stolenHash)
    {
      byte[] passwordAttemptHash = GetMD5Hash(passwordAttemptString);
      string passwordAttemptHashString = HashToString(passwordAttemptHash);

      bool result = CompareHashes(passwordAttemptHash, stolenHash);
      string passwordAttemptResult = passwordAttemptString + " " + passwordAttemptHashString;

      Console.WriteLine(passwordAttemptResult);
      File.AppendAllText(passwordAttemptsPath, passwordAttemptResult + Environment.NewLine);

      if (!result)
        return false;

      Console.WriteLine("Hashes match! Password: " + passwordAttemptString);
      Console.WriteLine(passwordAttemptHashString + " = " + HashToString(stolenHash));
      return true;
    }

  }

}