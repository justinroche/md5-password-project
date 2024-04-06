using System.Security.Cryptography;
using System.Text;

public static class Project2Helper {
	private static void Main() {
		Console.Write("Enter the stolen hash:\t");
		var stolenHashStr = Console.ReadLine()!;
		var stolenHash = Convert.FromHexString(stolenHashStr);

		for (; ; ) {
			Console.Write("Enter password:\t");
			var password = Console.ReadLine()!;

			if (TryLogin(password, stolenHash)) {
				Console.WriteLine("Login successful!");
				break;
			}
			else {
				Console.WriteLine("Login failed!");
			}
		}
	}

	private static bool TryLogin(string password, byte[] stolenHash) {
		// Encode the password into bytes using ASCII encoding
		var encoded = Encoding.ASCII.GetBytes(password);

		// Compute the MD5 hash of the encoded password
		var computedHash = MD5.HashData(encoded);

		// Compare the computed hash with the stolen hash
		for (var i = 0; i < 16; i++) {
			if (computedHash[i] != stolenHash[i]) {
				return false;
			}
		}

		return true;
	}
}
