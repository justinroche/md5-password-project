using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;

namespace MD5PasswordProject
{

  class Program
  {

    // Get passwords already attempted
    public static readonly string passwordAttemptsPath = "password_attempts_1.txt";
    public static readonly HashSet<string> passwordAttempts = new HashSet<string>(File.ReadAllLines(passwordAttemptsPath));

    // Get set of keywords
    public static readonly string keywordsPath = "keywords.txt";
    public static readonly string[] keywords = File.ReadAllLines(keywordsPath);

    // Get stolen hash
    public static readonly string stolenHashString = "7b0ca5c95a9398a2f32613d987428180";
    public static readonly byte[] stolenHash = StringTo16ByteHash(stolenHashString);

    static void Main(string[] args)
    {

      Console.WriteLine("Running password generation algorithm...");
      GeneratePasswords(FormatKeywords());
      Console.WriteLine("Loop completed.");

    }

    static void GeneratePasswords(string[] formattedKeywords)
    {
      // Test single keyword passwords.
      foreach (string keyword in formattedKeywords)
      {
        if (TryLogin(keyword))
          return;
      }

      // Test 2-keyword passwords.
      foreach (string keyword in formattedKeywords)
      {
        foreach (string keyword2 in formattedKeywords)
        {
          if (TryLogin(keyword + keyword2))
            return;
        }
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
    static bool PasswordAlreadyAttempted(string passwordAttemptString)
    {
      return passwordAttempts.Contains(passwordAttemptString);
    }

    // Validate format of target 1 password attempts.
    static bool ValidateTarget1String(string input)
    {
      // Between 5-10 characters.
      if (input.Length < 5 || input.Length > 10)
        return false;

      // Alphanumeric characters only.
      return new Regex("^[a-zA-Z0-9]*$").IsMatch(input);
    }

    // Validate format of target 2 password attempts.
    static bool ValidateTarget2String(string input)
    {
      // Between 12-18 characters.
      if (input.Length < 12 || input.Length > 18)
        return false;

      // Alphanumeric characters only.
      if (!Regex.IsMatch(input, "^[a-zA-Z0-9]+$"))
        return false;

      // At least one letter and one number.
      if (!Regex.IsMatch(input, "[a-zA-Z]") || !Regex.IsMatch(input, "[0-9]"))
        return false;

      // At least one uppercase and one lowercase letter.
      if (!Regex.IsMatch(input, "[a-z]") || !Regex.IsMatch(input, "[A-Z]"))
        return false;

      return true;
    }

    // Return MD5 hash of password as byte array.
    static byte[] GetMD5Hash(string password)
    {
      byte[] passwordBytes = Encoding.ASCII.GetBytes(password);
      byte[] hashBytes = MD5.HashData(passwordBytes);
      return hashBytes;
    }

    // Convert 16-byte hash to 32-character hash string.
    static string HashToString(byte[] md5Hash)
    {
      string computedHashString = md5Hash != null ? BitConverter.ToString(md5Hash).Replace("-", "") : string.Empty;
      return computedHashString;
    }

    // Convert 32-character hash string to 16-byte hash.
    static byte[] StringTo16ByteHash(string hashString)
    {
      if (hashString.Length != 32)
        throw new ArgumentException("Invalid hash string.");

      byte[] hashBytes = new byte[16];
      for (int i = 0; i < 16; i++)
        hashBytes[i] = Convert.ToByte(hashString.Substring(2 * i, 2), 16);
      return hashBytes;
    }

    // Check if hash byte arrays are equal.
    static bool CompareHashes(byte[] hash1, byte[] hash2)
    {
      for (int i = 0; i < 16; i++)
        if (hash1[i] != hash2[i])
          return false;

      return true;
    }

    // Log password attempt to console and password attempts file.
    static void LogPasswordAttempt(string passwordAttemptString, string passwordAttemptHashString)
    {
      string passwordAttemptResult = passwordAttemptString + " " + passwordAttemptHashString;
      Console.WriteLine(passwordAttemptResult);
      File.AppendAllText(passwordAttemptsPath, passwordAttemptResult + Environment.NewLine);
    }

    // Check if password attempt is valid and print result to console and password attempts file.
    static bool TryLogin(string passwordAttemptString)
    {

      // Check for correct formatting.
      if (!ValidateTarget1String(passwordAttemptString))
        return false;

      // Check if this password has already been attempted.
      if (PasswordAlreadyAttempted(passwordAttemptString))
        return false;

      // Get hash of password attempt and compare to stolen hash.
      byte[] passwordAttemptHash = GetMD5Hash(passwordAttemptString);
      string passwordAttemptHashString = HashToString(passwordAttemptHash);
      bool result = CompareHashes(passwordAttemptHash, stolenHash);

      // Log and store attempted password.
      LogPasswordAttempt(passwordAttemptString, passwordAttemptHashString);
      passwordAttempts.Add(passwordAttemptString);

      if (!result)
        return false;

      // If the password attempt was correct, notify the user and return true.
      Console.WriteLine("Hashes match! Password: " + passwordAttemptString);
      Console.WriteLine(passwordAttemptHashString + " = " + stolenHashString);
      return true;
    }

  }

}