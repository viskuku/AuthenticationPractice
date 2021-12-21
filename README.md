# AuthenticationPractice
JWT Authentication

# Following Packages are required
    <PackageReference Include="Microsoft.AspNetCore.Authentication.JwtBearer" Version="3.1.22" />
    <PackageReference Include="Microsoft.AspNetCore.Identity" Version="2.2.0" />
    <PackageReference Include="Microsoft.AspNetCore.Identity.EntityFrameworkCore" Version="3.1.22" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.SqlServer" Version="3.1.22" />
    <PackageReference Include="Microsoft.EntityFrameworkCore.Tools" Version="3.1.22">
    
  ## Microsoft.AspNetCore.Authentication.JwtBearer
         1. To add JwtBearerDefaults.AuthenticationScheme
  ## Microsoft.AspNetCore.Identity
         1. IdentityRole
         2. AddDefaultTokenProviders
         3. UserManager
         4. RoleManager
  ## Microsoft.AspNetCore.Identity.EntityFrameworkCore 
         1. to create IdentityDbContext<T>
  ## Microsoft.EntityFrameworkCore.SqlServer
         1. UseSqlServer
  ## Microsoft.EntityFrameworkCore.Tools
         1. Run the db migration
     
# Run the following commond to generate Identity Table in Sql Server
    add-migration "Initial"
    update-database

# Key Points 
      1. Setting JWT Token Property and Generate Token
      var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecurityKey"]));
                var token = new JwtSecurityToken
                    (
                     issuer: _configuration["JWT:ValidIssuer"],
                     audience: _configuration["JWT:ValidAudience"],
                     claims: authClaims,
                     expires: DateTime.Now.AddHours(5),
                     signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                    );
                var FinalToken = new 
                { 
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = DateTime.Now.AddHours(5)
                };
                
        2. Startup.cs steps
            a. //Entity Framwork - Add dbContext
            b. //Identity - Add Identity
            c. //Authentication  - Adding Authentication, use JWT Authentication Scheme
            d. //Adding Jwt Bearer - TokenValidationParameters, SymmetricSecurityKey
