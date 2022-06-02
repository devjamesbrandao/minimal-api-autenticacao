using System.Security.Claims;
using System.Text;
using Autenticacao_Identity;
using Autenticacao_Identity.Repositories;
using Autenticacao_Identity.Service;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();

// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen();

var key = Encoding.ASCII.GetBytes(Settings.Secret);

builder.Services.AddAuthentication(x =>
{
    x.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    x.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
}).AddJwtBearer(x =>
{
    x.RequireHttpsMetadata = false;
    x.SaveToken = true;
    x.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(key),
        ValidateIssuer = false,
        ValidateAudience = false
    };
});

builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("Admin", policy => policy.RequireRole("manager"));
    options.AddPolicy("Employee", policy => policy.RequireRole("employee"));
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();

app.UseAuthorization();

app.MapControllers();

app.MapPost("/login", (Usuario user) =>
{
    var usuario = UsuarioRepository.Get(user.Nome, user.Senha);

    if(usuario == null)
        return Results.NotFound(new { message = "Usuário não encontrado" });

    var token = TokenService.GenerateToken(usuario);

    user.Senha = "";

    return Results.Ok(new
    {
        user = usuario,
        token = token
    });
});

app.MapGet("/anonimo", () => { Results.Ok("Método público"); }).AllowAnonymous();

app.MapGet("/autenticado", (ClaimsPrincipal user) => 
{
    Results.Ok(new { message = $"Autenticado como {user.Identity.Name}" });
}).RequireAuthorization();

app.MapGet("/gerente", (ClaimsPrincipal user) => 
{
    Results.Ok(new { message = $"Autenticado como {user.Identity.Name}" });
}).RequireAuthorization("Admin");

app.MapGet("/funcionario", (ClaimsPrincipal user) => 
{
    Results.Ok(new { message = $"Autenticado como {user.Identity.Name}" });
}).RequireAuthorization("Employee");

app.Run();
