using Nine.AspNetCore;

// An MVC app: controllers and Razor views signed in with 9in, plus an API controller that takes 9in
// access tokens. Settings: the "Nine" section of appsettings.json or NINE_* environment variables.
var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllersWithViews();
builder.Services.AddAuthentication()
    .AddNineWebApp()
    .AddNineApi();
builder.Services.AddAuthorization();

var app = builder.Build();
app.UseAuthentication();
app.UseAuthorization();

app.MapNineWebApp();
app.MapDefaultControllerRoute();

app.Run();
