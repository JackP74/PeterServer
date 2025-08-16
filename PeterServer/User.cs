namespace PeterServer;

[Serializable]
internal class User
{
    public int? Id { get; set; }

    public string? Username { get; set; }

    public string? Password { get; set; }

    public User()
    {

    }

    internal User(int id, string username, string password)
    {
        Id = id;
        Username = username;
        Password = password;
    }
}