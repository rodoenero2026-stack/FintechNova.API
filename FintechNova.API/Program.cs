using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Npgsql;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

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
builder.Services.AddEndpointsApiExplorer();

builder.Services.AddSwaggerGen(c =>
{
    c.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Description = "Autenticación JWT. Escribe la palabra 'Bearer' seguida de un espacio y luego tu token.",
        Name = "Authorization",
        In = ParameterLocation.Header,
        Type = SecuritySchemeType.ApiKey,
        Scheme = "Bearer"
    });

    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference { Type = ReferenceType.SecurityScheme, Id = "Bearer" }
            },
            Array.Empty<string>()
        }
    });
});

var app = builder.Build();

// Swagger habilitado siempre (local y producción)
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

// Connection pool
var dataSource = NpgsqlDataSource.Create(
    builder.Configuration.GetConnectionString("DefaultConnection")!
);

app.MapPost("/api/registro", async (RegistroDto nuevoUsuario) =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    try
    {
        string sql = "INSERT INTO usuario (nombre, email, password) VALUES (@nombre, @email, @pass) RETURNING id_usuario;";
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("nombre", nuevoUsuario.Nombre);
        cmd.Parameters.AddWithValue("email", nuevoUsuario.Email);
        cmd.Parameters.AddWithValue("pass", nuevoUsuario.Password);

        int idCreado = Convert.ToInt32(await cmd.ExecuteScalarAsync());
        return Results.Ok(new { Mensaje = "Usuario creado con éxito", UsuarioId = idCreado });
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error al registrar: {ex.Message}");
    }
});

app.MapPost("/api/login", async (LoginDto loginInfo) =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    try
    {
        string sql = "SELECT nombre FROM usuario WHERE email = @email AND password = @pass;";
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("email", loginInfo.Email);
        cmd.Parameters.AddWithValue("pass", loginInfo.Password);

        var nombreUsuario = await cmd.ExecuteScalarAsync();

        if (nombreUsuario != null)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey!));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            var tokenString = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
            return Results.Ok(new { Token = tokenString, Usuario = nombreUsuario.ToString() });
        }
        return Results.Unauthorized();
    }
    catch (Exception ex)
    {
        return Results.Problem($"Error al iniciar sesión: {ex.Message}");
    }
});

app.MapPost("/api/prestamos/simular", async (SolicitudDto request) =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    using var tx = await conn.BeginTransactionAsync();
    try
    {
        string sqlSolicitud = @"INSERT INTO SOLICITUD_PRESTAMO 
            (id_usuario, monto_solicitado, plazo_meses, estado, curp, ine, recibo_luz_agua, comprobante_ingresos, estado_cuenta) 
            VALUES (@idUser, @monto, @plazo, 'APROBADA', @curp, @ine, @recibo, @comprobante, @estadoCuenta) 
            RETURNING id_solicitud;";
        using var cmdSolicitud = new NpgsqlCommand(sqlSolicitud, conn, tx);
        cmdSolicitud.Parameters.AddWithValue("idUser", request.IdUsuario);
        cmdSolicitud.Parameters.AddWithValue("monto", request.Monto);
        cmdSolicitud.Parameters.AddWithValue("plazo", request.Meses);
        cmdSolicitud.Parameters.AddWithValue("curp", request.CURP);
        cmdSolicitud.Parameters.AddWithValue("ine", request.INE);
        cmdSolicitud.Parameters.AddWithValue("recibo", request.ReciboLuzAgua);
        cmdSolicitud.Parameters.AddWithValue("comprobante", request.ComprobanteIngresos);
        cmdSolicitud.Parameters.AddWithValue("estadoCuenta", request.EstadoCuenta);
        int idSolicitud = Convert.ToInt32(await cmdSolicitud.ExecuteScalarAsync());

        string sqlPrestamo = @"INSERT INTO PRESTAMO 
            (id_solicitud, id_usuario, monto_aprobado, tasa_interes, saldo_pendiente) 
            VALUES (@idSol, @idUser, @monto, 15.5, @monto) 
            RETURNING id_prestamo;";
        using var cmdPrestamo = new NpgsqlCommand(sqlPrestamo, conn, tx);
        cmdPrestamo.Parameters.AddWithValue("idSol", idSolicitud);
        cmdPrestamo.Parameters.AddWithValue("idUser", request.IdUsuario);
        cmdPrestamo.Parameters.AddWithValue("monto", request.Monto);
        int idPrestamo = Convert.ToInt32(await cmdPrestamo.ExecuteScalarAsync());

        string sqlTransaccion = @"INSERT INTO TRANSACCION 
            (id_prestamo, tipo_transaccion, monto, estado) 
            VALUES (@idPrestamo, 'DESEMBOLSO', @monto, 'COMPLETADO');";
        using var cmdTrans = new NpgsqlCommand(sqlTransaccion, conn, tx);
        cmdTrans.Parameters.AddWithValue("idPrestamo", idPrestamo);
        cmdTrans.Parameters.AddWithValue("monto", request.Monto);
        await cmdTrans.ExecuteNonQueryAsync();

        await tx.CommitAsync();
        return Results.Ok(new { Mensaje = "Préstamo exitoso", PrestamoId = idPrestamo });
    }
    catch (Exception ex)
    {
        await tx.RollbackAsync();
        return Results.Problem(ex.Message);
    }
}).RequireAuthorization();

app.MapGet("/api/prestamos", async () =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    try
    {
        var prestamos = new List<object>();
        string sql = "SELECT id_prestamo, id_usuario, monto_aprobado, saldo_pendiente FROM PRESTAMO;";
        using var cmd = new NpgsqlCommand(sql, conn);
        using var reader = await cmd.ExecuteReaderAsync();

        while (await reader.ReadAsync())
        {
            prestamos.Add(new
            {
                IdPrestamo = reader.GetInt32(0),
                IdUsuario = reader.GetInt32(1),
                MontoAprobado = reader.GetDecimal(2),
                SaldoPendiente = reader.GetDecimal(3)
            });
        }
        return Results.Ok(prestamos);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
}).RequireAuthorization();

app.MapGet("/api/prestamos/{id}", async (int id) =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    try
    {
        string sql = "SELECT id_prestamo, id_usuario, monto_aprobado, saldo_pendiente FROM PRESTAMO WHERE id_prestamo = @id;";
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);
        using var reader = await cmd.ExecuteReaderAsync();

        if (await reader.ReadAsync())
        {
            return Results.Ok(new
            {
                IdPrestamo = reader.GetInt32(0),
                IdUsuario = reader.GetInt32(1),
                MontoAprobado = reader.GetDecimal(2),
                SaldoPendiente = reader.GetDecimal(3)
            });
        }
        return Results.NotFound(new { Mensaje = "Préstamo no encontrado" });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
}).RequireAuthorization();

app.MapPut("/api/prestamos/{id}", async (int id, PrestamoUpdateDto request) =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    try
    {
        string sql = "UPDATE PRESTAMO SET monto_aprobado = @monto, saldo_pendiente = @saldo WHERE id_prestamo = @id;";
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);
        cmd.Parameters.AddWithValue("monto", request.MontoAprobado);
        cmd.Parameters.AddWithValue("saldo", request.SaldoPendiente);

        int filasAfectadas = await cmd.ExecuteNonQueryAsync();
        if (filasAfectadas > 0)
            return Results.Ok(new { Mensaje = "Préstamo actualizado correctamente" });

        return Results.NotFound(new { Mensaje = "Préstamo no encontrado" });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
}).RequireAuthorization();

app.MapDelete("/api/prestamos/{id}", async (int id) =>
{
    using var conn = await dataSource.OpenConnectionAsync();
    try
    {
        string sqlTx = "DELETE FROM TRANSACCION WHERE id_prestamo = @id;";
        using var cmdTx = new NpgsqlCommand(sqlTx, conn);
        cmdTx.Parameters.AddWithValue("id", id);
        await cmdTx.ExecuteNonQueryAsync();

        string sql = "DELETE FROM PRESTAMO WHERE id_prestamo = @id;";
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.Parameters.AddWithValue("id", id);

        int filasAfectadas = await cmd.ExecuteNonQueryAsync();
        if (filasAfectadas > 0)
            return Results.Ok(new { Mensaje = "Préstamo eliminado del sistema" });

        return Results.NotFound(new { Mensaje = "Préstamo no encontrado" });
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message);
    }
}).RequireAuthorization();

app.Run();

public class RegistroDto
{
    public string Nombre { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class LoginDto
{
    public string Email { get; set; } = string.Empty;
    public string Password { get; set; } = string.Empty;
}

public class SolicitudDto
{
    public int IdUsuario { get; set; }
    public decimal Monto { get; set; }
    public int Meses { get; set; }
    public string CURP { get; set; } = string.Empty;
    public string INE { get; set; } = string.Empty;
    public string ReciboLuzAgua { get; set; } = string.Empty;
    public string ComprobanteIngresos { get; set; } = string.Empty;
    public string EstadoCuenta { get; set; } = string.Empty;
}

public class PrestamoUpdateDto
{
    public decimal MontoAprobado { get; set; }
    public decimal SaldoPendiente { get; set; }
}