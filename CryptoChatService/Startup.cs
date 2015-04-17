using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(CryptoChatService.Startup))]
namespace CryptoChatService
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
        }
    }
}