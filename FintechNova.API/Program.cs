using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Npgsql;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// 1. CONFIGURACIÓN DE SEGURIDAD (JWT)
var jwtSettings = builder.Configuration.GetSection("Jwt");
var secretKey = jwtSettings["Key"];

builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidateAudience = true,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            ValidIssuer = jwtSettings["Issuer"],
            ValidAudience = jwtSettings["Audience"],
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!))
        };
    });
builder.Services.AddAuthorization();

// 2. Configuración de Swagger (Súper básica para evitar errores de compatibilidad)
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

// 3. ACTIVAR LOS GUARDIAS EN LA APLICACIÓN
app.UseAuthentication();
app.UseAuthorization();

string connString = builder.Configuration.GetConnectionString("DefaultConnection")!;

// --- ENDPOINT 1: LOGIN (PARA OBTENER EL TOKEN) ---
app.MapPost("/api/login", (LoginDto loginInfo) =>
{
    // Simulamos que verificamos en la base de datos
    if (loginInfo.Email == "carlos@email.com" && loginInfo.Password == "12345")
    {
        // Si es correcto, le fabricamos su gafete (Token)
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: jwtSettings["Issuer"],
            audience: jwtSettings["Audience"],
            expires: DateTime.Now.AddHours(1), // El token caduca en 1 hora
            signingCredentials: creds
        );

        var tokenString = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
        return Results.Ok(new { Token = tokenString });
    }

    return Results.Unauthorized();
});

// --- ENDPOINT 2: SIMULACIÓN DE PRÉSTAMO (AHORA PROTEGIDO) ---
app.MapPost("/api/prestamos/simular", async (SolicitudDto request) =>
{
    using var conn = new NpgsqlConnection(connString);
    await conn.OpenAsync();
    using var tx = await conn.BeginTransactionAsync();

    try
    {
        // 1. Insertar Solicitud
        string sqlSolicitud = @"INSERT INTO SOLICITUD_PRESTAMO (id_usuario, monto_solicitado, plazo_meses, estado) 
                                VALUES (@idUser, @monto, @plazo, 'APROBADA') RETURNING id_solicitud;";
        using var cmdSolicitud = new NpgsqlCommand(sqlSolicitud, conn, tx);
        cmdSolicitud.Parameters.AddWithValue("idUser", request.IdUsuario);
        cmdSolicitud.Parameters.AddWithValue("monto", request.Monto);
        cmdSolicitud.Parameters.AddWithValue("plazo", request.Meses);
        int idSolicitud = Convert.ToInt32(await cmdSolicitud.ExecuteScalarAsync());

        // 2. Insertar Préstamo
        string sqlPrestamo = @"INSERT INTO PRESTAMO (id_solicitud, id_usuario, monto_aprobado, tasa_interes, saldo_pendiente) 
                               VALUES (@idSol, @idUser, @monto, 15.5, @monto) RETURNING id_prestamo;";
        using var cmdPrestamo = new NpgsqlCommand(sqlPrestamo, conn, tx);
        cmdPrestamo.Parameters.AddWithValue("idSol", idSolicitud);
        cmdPrestamo.Parameters.AddWithValue("idUser", request.IdUsuario);
        cmdPrestamo.Parameters.AddWithValue("monto", request.Monto);
        int idPrestamo = Convert.ToInt32(await cmdPrestamo.ExecuteScalarAsync());

        // 3. Registrar Transacción
        string sqlTransaccion = @"INSERT INTO TRANSACCION (id_prestamo, tipo_transaccion, monto, estado) 
                                  VALUES (@idPrestamo, 'DESEMBOLSO', @monto, 'COMPLETADO');";
        using var cmdTrans = new NpgsqlCommand(sqlTransaccion, conn, tx);
        cmdTrans.Parameters.AddWithValue("idPrestamo", idPrestamo);
        cmdTrans.Parameters.AddWithValue("monto", request.Monto);
        await cmdTrans.ExecuteNonQueryAsync();

        await tx.CommitAsync();
        return Results.Ok(new { Mensaje = "Préstamo procesado exitosamente", PrestamoId = idPrestamo });
    }
    catch (Exception ex)
    {
        await tx.RollbackAsync();
        return Results.Problem($"Error al procesar: {ex.Message}");
    }
}).RequireAuthorization(); // <--- ¡AQUÍ ESTÁ EL CANDADO!

app.Run();

// Clases de datos
public class SolicitudDto
{
    public int IdUsuario { get; set; }
    public decimal Monto { get; set; }
    public int Meses { get; set; }
}

public class LoginDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}