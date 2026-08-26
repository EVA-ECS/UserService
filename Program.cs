using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using StackExchange.Redis;
using UserService.Configuration;
using UserService.Services;

var builder = WebApplication.CreateBuilder(args);

builder.WebHost.UseUrls("http://0.0.0.0:8080");

var supabaseUrl =
    builder.Configuration["Supabase:Url"]?.TrimEnd('/');

if (string.IsNullOrWhiteSpace(supabaseUrl))
{
    throw new InvalidOperationException(
        "Die Konfiguration Supabase:Url fehlt."
    );
}

var redisConnectionString =
    builder.Configuration["Redis:ConnectionString"]
    ?? "redis:6379";

builder.Services
    .AddOptions<SupabaseOptions>()
    .Bind(
        builder.Configuration.GetSection(
            SupabaseOptions.SectionName
        )
    )
    .Validate(
        options => Uri.TryCreate(
            options.Url,
            UriKind.Absolute,
            out _
        ),
        "Supabase:Url ist ungültig."
    )
    .Validate(
        options => !string.IsNullOrWhiteSpace(
            options.PublishableKey
        ),
        "Supabase:PublishableKey fehlt."
    )
    .Validate(
        options => !string.IsNullOrWhiteSpace(
            options.SecretKey
        ),
        "Supabase:SecretKey fehlt."
    )
    .ValidateOnStart();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

builder.Services.AddHttpClient<
    ISupabaseAuthClient,
    SupabaseAuthClient
>(client =>
{
    client.Timeout = TimeSpan.FromSeconds(20);
});

builder.Services.AddSingleton<IConnectionMultiplexer>(
    ConnectionMultiplexer.Connect(redisConnectionString)
);

builder.Services.AddScoped<
    IUserDirectoryService,
    UserDirectoryService
>();

var supabaseIssuer = $"{supabaseUrl}/auth/v1";

builder.Services
    .AddAuthentication(
        JwtBearerDefaults.AuthenticationScheme
    )
    .AddJwtBearer(options =>
    {
        options.Authority = supabaseIssuer;
        options.Audience = "authenticated";
        options.RequireHttpsMetadata = true;

        options.TokenValidationParameters =
            new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                ValidateIssuer = true,
                ValidIssuer = supabaseIssuer,
                ValidateAudience = true,
                ValidAudience = "authenticated",
                ValidateLifetime = true
            };
    });

builder.Services.AddAuthorization();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

app.Run();