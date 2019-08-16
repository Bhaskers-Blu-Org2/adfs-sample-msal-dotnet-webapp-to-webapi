using Microsoft.Identity.Client;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.OpenIdConnect;
using System;
using System.Configuration;
using System.Diagnostics;
using System.Linq;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using System.Web;
using System.Web.Mvc;
using WebApp.Utils;

namespace WebApp.Controllers
{
    public class HomeController : Controller
    {
        public ActionResult Index()
        {
            return View();
        }

        [Authorize]
        public ActionResult About()
        {
            ViewBag.Name = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name").Value;
            ViewBag.AuthorizationRequest = string.Empty;

            // The object ID claim will only be emitted for work or school accounts at this time.
            Claim oid = ClaimsPrincipal.Current.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier");
            ViewBag.ObjectId = oid == null ? string.Empty : oid.Value;

            // The 'preferred_username' claim can be used for showing the user's primary way of identifying themselves
            ViewBag.Username = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name").Value;

            // The subject or nameidentifier claim can be used to uniquely identify the user
            ViewBag.Subject = ClaimsPrincipal.Current.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier").Value;
            return View();
        }

        [Authorize]
        [HttpGet]
        public async Task<ActionResult> AccessToken()
        {
            // Before we render the send email screen, we use the incremental consent to obtain and cache the access token with the correct scopes
            IConfidentialClientApplication app = MsalAppBuilder.BuildConfidentialClientApplication();
            AuthenticationResult result = null;
            var accounts = await app.GetAccountsAsync();
            string[] scopes = { String.Format(" {0}/openid", AuthenticationConfig.Resource) };

            try
            {
                // try to get an already cached token
                result = await app.AcquireTokenSilent(scopes, accounts.FirstOrDefault()).ExecuteAsync().ConfigureAwait(false);
                ViewBag.AccessToken = result.AccessToken;
                ViewBag.Environment = result.Account.Environment;

                // The 'preferred_username' claim can be used for showing the user's primary way of identifying themselves
                ViewBag.Username = result.Account.Username;
            }
            catch (MsalUiRequiredException ex)
            {
                // A MsalUiRequiredException happened on AcquireTokenSilentAsync.
                // This indicates you need to call AcquireTokenAsync to acquire a token
                Debug.WriteLine($"MsalUiRequiredException: {ex.Message}");

                try
                {
                    // Build the auth code request Uri
                    string authReqUrl = await OAuth2RequestManager.GenerateAuthorizationRequestUrl(scopes, app, this.HttpContext, Url);
                    ViewBag.AuthorizationRequest = authReqUrl;
                    ViewBag.Relogin = "true";
                }
                catch (MsalException msalex)
                {
                    Response.Write($"Error Acquiring Token:{System.Environment.NewLine}{msalex}");
                }
            }
            catch (Exception ex)
            {
                Response.Write($"Error Acquiring Token Silently:{System.Environment.NewLine}{ex}");
            }

            return View();
        }

    }
}