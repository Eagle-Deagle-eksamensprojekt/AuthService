using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using VaultSharp;
using VaultSharp.V1.AuthMethods.Token;
using VaultSharp.V1.AuthMethods;
using VaultSharp.V1.Commons;
using NLog.Web;
using NLog;
using NLog.Loki;

var builder = WebApplication.CreateBuilder(args);

var logger = NLog.LogManager.Setup().LoadConfigurationFromAppSettings()
        .GetCurrentClassLogger();
        logger.Debug("init main"); // NLog setup

// Hent Vault-konfigurationer
var vaultUrl = builder.Configuration["VaultURL"];  // Vault URL
//var vaultUrl = "http://vaulthost:8300";  // Vault URL //skal gøres til miljøvariabel 
//var vaultToken = builder.Configuration["VAULT_DEV_ROOT_TOKEN_ID"];  // Vault-token (tilpas som nødvendigt) //skal gøres til miljøvariabel // nu sat til miljøvariabel i .env til compose
var vaultToken = "00000000-0000-0000-0000-000000000000";


// Opsæt Vault klient
var authMethod = new TokenAuthMethodInfo(vaultToken);
var vaultClientSettings = new VaultClientSettings(vaultUrl, authMethod);
var vaultClient = new VaultClient(vaultClientSettings);

// Hent secret og issuer fra Vault
var kv2Secret = await vaultClient.V1.Secrets.KeyValue.V2.ReadSecretAsync(path: "Secrets", mountPoint: "secret");
var jwtSecret = kv2Secret.Data.Data["jwtSecret"]?.ToString() ?? throw new Exception("jwtSecret not found in Vault.");
var jwtIssuer = kv2Secret.Data.Data["jwtIssuer"]?.ToString() ?? throw new Exception("jwtIssuer not found in Vault.");


// JWT setup
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtIssuer,
            ValidAudience = "http://localhost",  // Tilpas som nødvendigt
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSecret))
        };
    });

builder.Services.AddAuthorization();


// Add HTTP-client step 1 modul 12.1.E
    builder.Services.AddHttpClient(); //tjek
// Add services to the container.
builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer(); 
builder.Services.AddSwaggerGen();

// Registrér at I ønsker at bruge NLOG som logger fremadrettet (før builder.build)
builder.Logging.ClearProviders();
builder.Host.UseNLog();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();
app.Run();