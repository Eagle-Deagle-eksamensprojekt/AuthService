using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Text.Json;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.Commons;
using AuthService.Models;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;


namespace AuthService.Controllers;

[ApiController]
[Route("[controller]")]
public class AuthController : ControllerBase
{
    // tilføje en HttpClient
    private readonly IHttpClientFactory _httpClientFactory; //tjek

    private readonly IConfiguration _config;
    private readonly ILogger<AuthController> _logger;
    string mySecret = "Not set";
    string myIssuer = "Not set";


    public AuthController(ILogger<AuthController> logger, IConfiguration config, IHttpClientFactory httpClientFactory)
    {
        _logger = logger;
        _config = config;
        _httpClientFactory = httpClientFactory; // tjek
    }
    private async Task GetVaultSecrets() 
{
    var vaultEndPoint = _config["VaultURL"];
    _logger.LogInformation("Connection to: {0} ", vaultEndPoint);
    var token = "00000000-0000-0000-0000-000000000000";

    var httpClientHandler = new HttpClientHandler
    {
        ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
    };

    var authMethod = new TokenAuthMethodInfo(token);
    var vaultClientSettings = new VaultClientSettings(vaultEndPoint, authMethod)
    {
        MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler) { BaseAddress = new Uri(vaultEndPoint!) }
    };

    IVaultClient vaultClient = new VaultClient(vaultClientSettings);

    var kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "Secrets", mountPoint: "secret");
    
    // Gem værdierne i klassevariablerne
    mySecret = kv2Secret.Data.Data["jwtSecret"]?.ToString() ?? throw new Exception("jwtSecret not found in Vault.");
    myIssuer = kv2Secret.Data.Data["jwtIssuer"]?.ToString() ?? throw new Exception("jwtIssuer not found in Vault.");

    _logger.LogInformation("Vault JWT Secret: {JwtSecret}", mySecret);
    _logger.LogInformation("Vault JWT Issuer: {JwtIssuer}", myIssuer);
}


    // Indsat fra opgave E i modul 12.1
    // ændret d. 14/11/2024 tilpasset af chat så den sender email i stedet for username
    private async Task<User?> GetUserData(LoginModel login)
    {
        // Tjek om brugeren eksisterer
        var existsUrl = $"{_config["UserServiceEndpoint"]}/byEmail?email={login.UserEmail}";
        _logger.LogInformation("Checking if user exists at: {ExistsUrl}", existsUrl);
        
        var client = _httpClientFactory.CreateClient();
        HttpResponseMessage response;

        try
        {
            client.DefaultRequestHeaders.Add("Accept", "application/json");
            response = await client.GetAsync(existsUrl);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, ex.Message);
            return null;
        }

if (response.IsSuccessStatusCode)
        {
            string responseContent = await response.Content.ReadAsStringAsync();
            _logger.LogInformation("Response content: {ResponseContent}", responseContent);

            try
            {
                // Forsøg at deserialisere til User
                var user = JsonSerializer.Deserialize<User>(responseContent);
                if (user == null)
                {
                    _logger.LogInformation("User with email {Email} does not exist.", login.UserEmail);
                    return null;
                }

                _logger.LogInformation("User data successfully deserialized.");
                return user;
            }
            catch (JsonException ex)
            {
                _logger.LogError(ex, "Failed to deserialize user data.");
                return null;
            }
        }
        _logger.LogWarning("Failed to check if user exists.");
        return null;
    }



    // Opdateret Login-metode
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        // Log brug af email til console for at sikre korrekt værdi
        _logger.LogInformation("Attempting login with email: {Email}", login.UserEmail);
        
        // Hent brugerdata baseret på email
        var user = await GetUserData(login);
        if (user == null)
        {
            _logger.LogWarning("User with email {Email} not found", login.UserEmail);
            return Unauthorized("Invalid email or password.");
        }

        // Valider passwordet
        var hashedInputPassword = Convert.ToBase64String(KeyDerivation.Pbkdf2(
            password: login.Password!,
            salt: Convert.FromBase64String(user.Salt),
            prf: KeyDerivationPrf.HMACSHA256,
            iterationCount: 100000,
            numBytesRequested: 256 / 8));

        if (user.Password != hashedInputPassword)
        {
            _logger.LogWarning("Invalid password for email {Email}", login.UserEmail);
            return Unauthorized("Invalid email or password.");
        }

        // Generer JWT-token, hvis login er succesfuldt
        var token = await GenerateJwtToken(login.UserEmail!);
        _logger.LogInformation("Login successful for email: {Email}", login.UserEmail);
        return Ok(new { token });
    }



    private async Task<string> GenerateJwtToken(string username)
    {
        if (string.IsNullOrEmpty(username))
        {
            _logger.LogError("Username is null or empty.");
            throw new ArgumentNullException(nameof(username));
        }

        await GetVaultSecrets();
        
        /*
        if (string.IsNullOrEmpty(mySecret) || string.IsNullOrEmpty(myIssuer))
        {
            throw new ArgumentNullException("Secret or Issuer is not set.");
        }
        */

        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(mySecret));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

        var claims = new[]
        {
            new Claim(ClaimTypes.NameIdentifier, username)
        };

        var token = new JwtSecurityToken(
            myIssuer,
            "http://localhost",
            claims,
            expires: DateTime.Now.AddMinutes(15),
            signingCredentials: credentials);

        return new JwtSecurityTokenHandler().WriteToken(token); // Der bliver returneret ekstra information, ved ikke hvorfor
    }

    public class LoginModel
    {
        public string? UserEmail { get; set; }
        public string? Password { get; set; }
    }
}
