using BlazorAuthSample.Data;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using System.Security.Claims;
using System.Threading.Tasks;

namespace BlazorAuthSample
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        // For more information on how to configure your application, visit https://go.microsoft.com/fwlink/?LinkID=398940
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddRazorPages();
            services.AddServerSideBlazor();
            services.AddSingleton<WeatherForecastService>();

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = _ => false;
                options.MinimumSameSitePolicy = Microsoft.AspNetCore.Http.SameSiteMode.None;
            });

            services.AddAuthentication(options =>
            {
                options.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultSignInScheme = CookieAuthenticationDefaults.AuthenticationScheme;
                options.DefaultChallengeScheme = OpenIdConnectDefaults.AuthenticationScheme;
            })
            .AddCookie()
            .AddOpenIdConnect(o => 
                {
                    o.Authority = Configuration.GetValue<string>("Authentication:Authority");
                    o.ClientId = Configuration.GetValue<string>("Authentication:ClientId");
                    o.ClientSecret = Configuration.GetValue<string>("Authentication:ClientSecret");
                    o.RequireHttpsMetadata = Configuration.GetValue<bool>("Authentication:RequireHttpsMetadata"); // disable only in dev env
                    o.ResponseType = OpenIdConnectResponseType.Code;
                    o.GetClaimsFromUserInfoEndpoint = true;
                    o.SaveTokens = false;
                    o.MapInboundClaims = true;
                    o.Scope.Clear();
                    o.Scope.Add("openid");
                    o.Scope.Add("profile");
                    o.Scope.Add("email");
                    o.Scope.Add("roles");
                    o.TokenValidationParameters.ValidIssuer = Configuration.GetValue<string>("Authentication:ValidIssuer");
                    o.MetadataAddress = Configuration.GetValue<string>("Authentication:MetadataAddress");
                    o.Events = new OpenIdConnectEvents
                    {
                        OnUserInformationReceived = context =>
                        {
                            MapKeyCloakRolesToRoleClaims(context);
                            return Task.CompletedTask;
                        }
                    };
                });

            services.AddAuthorization();
        }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }
            else
            {
                app.UseExceptionHandler("/Error");
                // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseCookiePolicy();
            app.UseAuthentication();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapBlazorHub();
                endpoints.MapFallbackToPage("/_Host");
            });
        }

        private static void MapKeyCloakRolesToRoleClaims(UserInformationReceivedContext context)
        {
            if (context.Principal.Identity is not ClaimsIdentity claimsIdentity) return;

            if (context.User.RootElement.TryGetProperty("preferred_username", out var username))
            {
                claimsIdentity.AddClaim(new Claim(ClaimTypes.Name, username.ToString()));
            }

            if (context.User.RootElement.TryGetProperty("realm_access", out var realmAccess)
                && realmAccess.TryGetProperty("roles", out var globalRoles)) 
            {
                foreach (var role in globalRoles.EnumerateArray())
                {
                    claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));
                }
            }

            if (context.User.RootElement.TryGetProperty("resource_access", out var clientAccess)
                && clientAccess.TryGetProperty(context.Options.ClientId, out var client)
                && client.TryGetProperty("roles", out var clientRoles)) 
            {
                foreach (var role in clientRoles.EnumerateArray())
                {
                    claimsIdentity.AddClaim(new Claim(ClaimTypes.Role, role.ToString()));
                }
            }
        }
    }
}
