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
        // Vault setup - konfigurer Vault-klient for at hente hemmeligheder
        var vaultEndPoint = _config["VaultURL"]; // Vault-server URL
        _logger.LogInformation("Connection to: {0} ", vaultEndPoint);
        var token = "00000000-0000-0000-0000-000000000000"; // Vault-token

        var httpClientHandler = new HttpClientHandler
        {
            ServerCertificateCustomValidationCallback = (message, cert, chain, sslPolicyErrors) => true
        };

        var authMethod = new TokenAuthMethodInfo(token);
        var vaultClientSettings = new VaultClientSettings(vaultEndPoint, authMethod)
        {
            MyHttpClientProviderFunc = handler => new HttpClient(httpClientHandler) { BaseAddress = new Uri(vaultEndPoint!) } // lav tjek om vaultEndPoint er null
        };

        IVaultClient vaultClient = new VaultClient(vaultClientSettings);

        // Hent secret og issuer fra Vault
        Secret<SecretData> kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "hemmeligheder", mountPoint: "secret");
        mySecret = kv2Secret.Data.Data["secret"]?.ToString() ?? throw new Exception("Secret not found in Vault."); // Vigtigt, her skal "Secret" og "Issuer" være skrevet præcis som inde på vault
        myIssuer = kv2Secret.Data.Data["issuer"]?.ToString() ?? throw new Exception("Issuer not found in Vault.");

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
            // Deserialiser respons som bool
            string responseContent = await response.Content.ReadAsStringAsync();
            bool userExists = JsonSerializer.Deserialize<bool>(responseContent);

            if (!userExists) // Hvis brugeren ikke findes, returner null
            {
                _logger.LogInformation("User with email {Email} does not exist.", login.UserEmail);
                return null;
            }
            
            // Hvis brugeren findes, hent brugerdata
            var userDataUrl = $"{_config["UserServiceEndpoint"]}/byEmail?email={login.UserEmail}";
            _logger.LogInformation("Retrieving user data from: {UserDataUrl}", userDataUrl);

            response = await client.GetAsync(userDataUrl);
            if (response.IsSuccessStatusCode)
            {
                try
                {
                    string userJson = await response.Content.ReadAsStringAsync();
                    return JsonSerializer.Deserialize<User>(userJson); // Forsøg at deserialisere til User-objekt
                }
                catch (Exception ex)
                {
                    _logger.LogError(ex, ex.Message);
                }
            }
        }
        return null;
    }



    // Opdateret Login-metode
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<IActionResult> Login([FromBody] LoginModel login)
    {
        // Log brug af email til console for at sikre korrekt værdi
        _logger.LogInformation("Attempting login with email: {Email}", login.UserEmail);
        
        // Tjekker om brugeren eksisterer med den givne email
        var user = await GetUserData(login);
        if (user != null && login.Password == "123") // Opret et bedre password-tjek på sigt
        {
            var token = await GenerateJwtToken(login.UserEmail);
            _logger.LogInformation("Login successful for email: {Email}", login.UserEmail);
            return Ok(new { token });
        }
        _logger.LogWarning("Login failed for email: {Email}", login.UserEmail);
        return Unauthorized();
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
