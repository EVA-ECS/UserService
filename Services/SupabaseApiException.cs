using System.Net;

namespace UserService.Services;

public sealed class SupabaseApiException : Exception
{
    public SupabaseApiException(HttpStatusCode statusCode)
        : base($"Supabase antwortete mit HTTP {(int)statusCode}.")
    {
        StatusCode = statusCode;
    }

    public HttpStatusCode StatusCode { get; }
}