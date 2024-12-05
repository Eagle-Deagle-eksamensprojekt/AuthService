using NUnit.Framework;
using Moq;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Configuration;
using authServiceAPI.Controllers;
using authServiceAPI.Models;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;

namespace authServiceAPI.Test
{
    public class AuthControllerTests
    {
        private Mock<ILogger<AuthController>> _mockLogger;
        private Mock<IConfiguration> _mockConfig;
        private Mock<IHttpClientFactory> _mockHttpClientFactory;
        private AuthController _controller;

        [SetUp]
        public void Setup()
        {
            _mockLogger = new Mock<ILogger<AuthController>>();
            _mockConfig = new Mock<IConfiguration>();
            _mockHttpClientFactory = new Mock<IHttpClientFactory>();

            _controller = new AuthController(
                _mockLogger.Object,
                _mockConfig.Object,
                _mockHttpClientFactory.Object
            );
        }

        [Test]
        public async Task Login_ShouldReturnOk_WhenPasswordIsValid()
        {
            // Arrange
            var loginRequest = new LoginModel
            {
                UserEmail = "test@example.com",
                Password = "123" // Simulate a valid password
            };

            // Mock GetUserData to return a valid user
            var mockUser = new User
            {
                Email = "test@example.com",
                PasswordHash = "hashedPassword"  // Simulate a correct hashed password
            };

            // Mock IHttpClientFactory behavior if needed (depending on how you're calling external services)

            // Act
            var result = await _controller.Login(loginRequest);

            // Assert
            Assert.IsInstanceOf<OkObjectResult>(result); // Check if it returns a 200 OK response
        }

        [Test]
        public async Task Login_ShouldReturnUnauthorized_WhenPasswordIsInvalid()
        {
            // Arrange
            var loginRequest = new LoginModel
            {
                UserEmail = "test@example.com",
                Password = "wrongPassword"  // Simulate an invalid password
            };

            var mockUser = new User
            {
                Email = "test@example.com",
                PasswordHash = "hashedPassword"  // Simulate a correct hashed password
            };

            // Mock the GetUserData to return the mock user

            // Act
            var result = await _controller.Login(loginRequest);

            // Assert
            Assert.IsInstanceOf<UnauthorizedResult>(result); // Check if it returns a 401 Unauthorized response
        }
    }
}
