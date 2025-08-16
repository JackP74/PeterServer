namespace PeterServer;

internal static class UserManagement
{
    private static readonly string UsersPath = Path.Combine(AppDomain.CurrentDomain.BaseDirectory, "users.ptr");
    private static User[] Users = [];

    /// <summary>
    /// Loads, decrypts, and deserializes user data from the file into memory.
    /// </summary>
    /// <remarks>
    /// If the user file does not exist, is corrupt, or fails decryption/deserialization,
    /// it will be overwritten with a new, empty user file to ensure application stability.
    /// </remarks>
    internal static void LoadUsers()
    {
        if (!File.Exists(UsersPath))
        {
            SaveUsers();
        }

        var rawUsers = File.ReadAllText(UsersPath);
        var decryptedUsers = Extensions.Decrypt(rawUsers);
        if (decryptedUsers == null)
        {
            Extensions.WriteError("Invalid users file found, overwritten");
            SaveUsers();
            return;
        }

        var users = Extensions.Deserialize<User[]>(decryptedUsers);
        if (users == null)
        {
            Extensions.WriteError("Invalid users file found, overwritten");
            SaveUsers();
            return;
        }

        Users = users;
    }

    /// <summary>
    /// Serializes, encrypts, and saves the current in-memory user list to the user file.
    /// </summary>
    internal static void SaveUsers()
    {
        var decryptedUsers = Extensions.Serialize(Users);
        if (decryptedUsers == null) return;

        var rawUsers = Extensions.Encrypt(decryptedUsers);
        if (rawUsers == null) return;

        File.WriteAllText(UsersPath, rawUsers);
    }

    private static bool IsUserValid(string? username, string? password)
    {
        if (string.IsNullOrWhiteSpace(username) || string.IsNullOrEmpty(password)) return false;

        if (username.Length < 5 || password.Length < 8) return false;

        return true;
    }

    private static bool UserExists(string? username)
    {
        if (string.IsNullOrWhiteSpace(username)) return false;

        return Users.Where(x => x.Username == username).Any();
    }

    internal static bool AddUser(string username, string password)
    {
        if (!IsUserValid(username, password)) return false;

        if (UserExists(username)) return false;

        var finalUsername = Extensions.ComputeSha256Hash(username);
        var finalPassword = Extensions.ComputeSha256Hash(password);

        Users = [.. Users, new User(Users.Length, finalUsername, finalPassword)];

        return true;
    }
}
