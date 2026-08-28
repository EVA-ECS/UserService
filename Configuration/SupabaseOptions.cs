namespace UserService.Configuration;

public sealed class SupabaseOptions
{
    public const string SectionName = "Supabase";

    public string Url { get; init; } = string.Empty;
    public string PublishableKey { get; init; } = string.Empty;
    public string SecretKey { get; init; } = string.Empty;
}