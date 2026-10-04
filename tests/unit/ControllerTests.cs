using System.Net;
using System.Security.Claims;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using UserService.Controllers;
using UserService.Models;
using UserService.Services;
using Xunit;

namespace UserService.Tests;

public sealed class ControllerTests
{
    private static readonly AuthSessionResponse Session = new("access", "refresh", 12345, new("alice", "alice@example.test"));
    private static AuthController Auth(Mock<ISupabaseAuthClient> client) => new(client.Object, NullLogger<AuthController>.Instance)
    { ControllerContext = new() { HttpContext = new DefaultHttpContext() } };

    [Fact]
    public async Task RegisterNormalizesEmailAndPreservesPassword()
    {
        var client = new Mock<ISupabaseAuthClient>(MockBehavior.Strict);
        client.Setup(x => x.RegisterAsync("alice@example.test", "Password1!", default))
            .ReturnsAsync(new RegisterResponse("confirm email", true));
        var result = await Auth(client).Register(new() { Email = " ALICE@EXAMPLE.TEST ", Password = "Password1!" }, default);
        Assert.True(Assert.IsType<RegisterResponse>(Assert.IsType<OkObjectResult>(result.Result).Value).RequiresEmailConfirmation);
        client.VerifyAll();
    }

    [Fact]
    public async Task LoginNormalizesEmailAndReturnsSession()
    {
        var client = new Mock<ISupabaseAuthClient>(MockBehavior.Strict);
        client.Setup(x => x.LoginAsync("alice@example.test", "Password1!", default)).ReturnsAsync(Session);
        var result = await Auth(client).Login(new() { Email = " ALICE@EXAMPLE.TEST ", Password = "Password1!" }, default);
        Assert.Equal(Session, Assert.IsType<OkObjectResult>(result.Result).Value);
        client.VerifyAll();
    }

    [Fact]
    public async Task RefreshPassesOnlyRefreshToken()
    {
        var client = new Mock<ISupabaseAuthClient>(MockBehavior.Strict);
        client.Setup(x => x.RefreshAsync("refresh", default)).ReturnsAsync(Session);
        Assert.Equal(Session, Assert.IsType<OkObjectResult>((await Auth(client).Refresh(new() { RefreshToken = "refresh" }, default)).Result).Value);
        client.VerifyAll();
    }

    [Theory]
    [InlineData("register", 400, 400)] [InlineData("register", 503, 503)] [InlineData("register", 0, 503)]
    [InlineData("login", 401, 401)] [InlineData("login", 503, 503)] [InlineData("login", 0, 503)]
    [InlineData("refresh", 401, 401)] [InlineData("refresh", 503, 503)] [InlineData("refresh", 0, 503)]
    public async Task AuthenticationFailuresReturnSafeStatusWithoutLeakingError(string action, int upstream, int expected)
    {
        Exception error = upstream == 0 ? new IOException("private upstream detail") : new SupabaseApiException((HttpStatusCode)upstream);
        var client = new Mock<ISupabaseAuthClient>();
        client.Setup(x => x.RegisterAsync(It.IsAny<string>(), It.IsAny<string>(), default)).ThrowsAsync(error);
        client.Setup(x => x.LoginAsync(It.IsAny<string>(), It.IsAny<string>(), default)).ThrowsAsync(error);
        client.Setup(x => x.RefreshAsync(It.IsAny<string>(), default)).ThrowsAsync(error);
        var result = await InvokeAuth(Auth(client), action);
        var response = Assert.IsAssignableFrom<ObjectResult>(result);
        Assert.Equal(expected, response.StatusCode);
        Assert.DoesNotContain("private upstream detail", Assert.IsType<ApiErrorResponse>(response.Value).Message);
    }

    [Theory]
    [InlineData("register")] [InlineData("login")] [InlineData("refresh")]
    public async Task AuthenticationCancellationIsNotAnUpstreamFailure(string action)
    {
        var client = new Mock<ISupabaseAuthClient>();
        var error = new OperationCanceledException();
        client.Setup(x => x.RegisterAsync(It.IsAny<string>(), It.IsAny<string>(), default)).ThrowsAsync(error);
        client.Setup(x => x.LoginAsync(It.IsAny<string>(), It.IsAny<string>(), default)).ThrowsAsync(error);
        client.Setup(x => x.RefreshAsync(It.IsAny<string>(), default)).ThrowsAsync(error);
        await Assert.ThrowsAsync<OperationCanceledException>(() => InvokeAuth(Auth(client), action));
    }

    [Theory]
    [InlineData("")] [InlineData("Basic token")]
    public async Task LogoutWithoutBearerDoesNotCallUpstream(string header)
    {
        var client = new Mock<ISupabaseAuthClient>(MockBehavior.Strict);
        var controller = Auth(client);
        controller.Request.Headers.Authorization = header;
        Assert.IsType<UnauthorizedResult>(await controller.Logout(default));
    }

    [Theory]
    [InlineData(0)] [InlineData(500)] [InlineData(-1)]
    public async Task LogoutPassesTrimmedTokenAndHandlesUpstreamFailures(int failure)
    {
        var client = new Mock<ISupabaseAuthClient>();
        var call = client.Setup(x => x.SignOutAsync("access", default));
        if (failure > 0) call.ThrowsAsync(new SupabaseApiException((HttpStatusCode)failure));
        else if (failure < 0) call.ThrowsAsync(new IOException());
        else call.Returns(Task.CompletedTask);
        var controller = Auth(client);
        controller.Request.Headers.Authorization = "bEaReR  access ";
        var result = await controller.Logout(default);
        if (failure == 0) Assert.IsType<NoContentResult>(result);
        else Assert.Equal(503, Assert.IsType<ObjectResult>(result).StatusCode);
        client.Verify(x => x.SignOutAsync("access", default), Times.Once);
    }

    [Theory]
    [InlineData("users")] [InlineData("publish")]
    public async Task DirectoryEndpointsRequireAUserClaim(string action)
    {
        var controller = Users(new Mock<IUserDirectoryService>(MockBehavior.Strict), null);
        Assert.IsType<UnauthorizedResult>(await InvokeUsers(controller, action));
    }

    [Theory]
    [InlineData("users")] [InlineData("publish")] [InlineData("key")]
    public async Task DirectoryEndpointsReturnSuccessOrSafeFailure(string action)
    {
        var directory = new Mock<IUserDirectoryService>();
        var key = new PublicKeyResponse("alice", "key-id", "encoded", DateTimeOffset.UtcNow);
        directory.Setup(x => x.GetUsersAsync("alice", default)).ReturnsAsync([new("bob", "Bob", true)]);
        directory.Setup(x => x.PublishPublicKeyAsync("alice", It.IsAny<PublishPublicKeyRequest>(), default)).ReturnsAsync(key);
        directory.Setup(x => x.GetPublicKeyAsync(It.IsAny<string>(), default)).ReturnsAsync(key);
        Assert.IsType<OkObjectResult>(await InvokeUsers(Users(directory, "alice"), action));
        directory.Setup(x => x.GetUsersAsync("alice", default)).ThrowsAsync(new IOException());
        directory.Setup(x => x.PublishPublicKeyAsync("alice", It.IsAny<PublishPublicKeyRequest>(), default)).ThrowsAsync(new IOException());
        directory.Setup(x => x.GetPublicKeyAsync(It.IsAny<string>(), default)).ThrowsAsync(new IOException());
        Assert.Equal(503, Assert.IsType<ObjectResult>(await InvokeUsers(Users(directory, "alice"), action)).StatusCode);
    }

    [Fact]
    public async Task PublicKeyEndpointRejectsInvalidKeyAndReturnsNotFoundForAbsentKey()
    {
        var directory = new Mock<IUserDirectoryService>();
        directory.Setup(x => x.PublishPublicKeyAsync("alice", It.IsAny<PublishPublicKeyRequest>(), default)).ThrowsAsync(new ArgumentException("bad key"));
        var controller = Users(directory, "alice");
        Assert.IsType<BadRequestObjectResult>((await controller.PublishPublicKey(new() { PublicKey = "bad" }, default)).Result);
        Assert.IsType<NotFoundObjectResult>((await controller.GetPublicKey(Guid.NewGuid(), default)).Result);
        Assert.IsType<OkObjectResult>(new HealthController().Health());
    }

    private static UsersController Users(Mock<IUserDirectoryService> directory, string? userId)
    {
        var context = new DefaultHttpContext();
        if (userId is not null) context.User = new(new ClaimsIdentity([new Claim("sub", userId)], "unit"));
        return new(directory.Object, NullLogger<UsersController>.Instance) { ControllerContext = new() { HttpContext = context } };
    }
    private static async Task<IActionResult> InvokeAuth(AuthController controller, string action) => action switch
    {
        "register" => (await controller.Register(new() { Email = "alice@example.test", Password = "password" }, default)).Result!,
        "login" => (await controller.Login(new() { Email = "alice@example.test", Password = "password" }, default)).Result!,
        _ => (await controller.Refresh(new() { RefreshToken = "refresh" }, default)).Result!
    };
    private static async Task<IActionResult> InvokeUsers(UsersController controller, string action) => action switch
    {
        "users" => (await controller.GetUsers(default)).Result!,
        "publish" => (await controller.PublishPublicKey(new() { PublicKey = "key" }, default)).Result!,
        _ => (await controller.GetPublicKey(Guid.NewGuid(), default)).Result!
    };
}
