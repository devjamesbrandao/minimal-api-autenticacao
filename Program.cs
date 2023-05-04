using System.Reflection;
using System.Security.Claims;
using System.Text;
using Autenticacao_Identity.DTO;
using Autenticacao_Identity.Repositories;
using Autenticacao_Identity.Service;
using Autenticacao_Identity.Utils;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();

builder.Services.AddEndpointsApiExplorer();

// Adicionando configuração do swagger
builder.Services.AddSwaggerGen(x => 
{
    x.SwaggerDoc("v1", new OpenApiInfo { Title = "Minimal API com autenticação e autorização", Version = "v1" });

    x.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = @"JWT Authorization header usando o padrão Bearer.  
                    Adicione 'Bearer' [espaço] e então seu token no input abaixo.
                    Exemplo: 'Bearer 12345abcdef'",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    x.AddSecurityRequirement(new OpenApiSecurityRequirement()
    {
        {
        new OpenApiSecurityScheme
        {
            Reference = new OpenApiReference
            {
                Type = ReferenceType.SecurityScheme,
                Id = "Bearer"
            },
            Scheme = "oauth2",
            Name = "Bearer",
            In = ParameterLocation.Header,

            },
            new List<string>()
        }
    });

    var xmlFilename = $"{Assembly.GetExecutingAssembly().GetName().Name}.xml";
    
    x.IncludeXmlComments(Path.Combine(AppContext.BaseDirectory, xmlFilename));
});

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

app.MapAutenticacaoRoutes();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseAuthentication();

app.UseAuthorization();

app.Run();

public static class AutenticaoEndpoints
{
    public static void MapAutenticacaoRoutes(this IEndpointRouteBuilder app)
    {
        app.MapPost("/login", Login);

        app.MapGet("/anonimo", Anonimo).AllowAnonymous();

        app.MapGet("/autenticado", UsuarioAutorizado).RequireAuthorization();

        app.MapGet("/gerente", UsuarioGerente).RequireAuthorization("Admin");

        app.MapGet("/funcionario", UsuarioFuncionario).RequireAuthorization("Employee");
    }

    /// <summary>
    /// Permite realizar acesso de forma anônima
    /// </summary>
    /// <returns></returns>
    private static IResult Anonimo () => Results.Ok("Método público");

    /// <summary>
    /// Permite acesso com a Policy Admin
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    private static IResult UsuarioGerente (ClaimsPrincipal user) => 
        Results.Ok(new { message = $"Autenticado como {user.Identity.Name}" });

    /// <summary>
    /// Permite acesso com a Policy Employee
    /// </summary>
    /// <param name="user"></param>
    /// <returns></returns>
    private static IResult UsuarioFuncionario (ClaimsPrincipal user) => 
        Results.Ok(new { message = $"Autenticado como {user.Identity.Name}" });

    /// <summary>
    /// Realiza login do usuário
    /// </summary>
    /// <param name="userLogin"></param>
    /// <remarks>
    /// {
    ///     "nome": "Kakashi",
    ///     "senha": "123"
    /// }
    /// </remarks>
    /// <returns></returns>
    private static IResult Login (UserLogin userLogin)
    {
        var user = UsuarioRepository.Get(userLogin.Nome, userLogin.Senha);

        if(user is null) return Results.NotFound(new { message = "Usuário não encontrado" });

        var token = TokenService.GenerateToken(user);

        user.CleanPassword();

        return Results.Ok(new
        {
            user = user,
            token = token
        });
    }

    /// <summary>
    /// Permite apenas usuários autenticados
    /// </summary>
    /// <param name="user">Claims do usuário</param>
    /// <response code="200">The response with message</response>
    private static IResult UsuarioAutorizado (ClaimsPrincipal user) => 
        Results.Ok(new { message = $"Autenticado como {user.Identity.Name}" });
}