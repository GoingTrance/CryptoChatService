using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using System.IO;
using System.Security.Cryptography;
using System.Runtime.Serialization.Formatters.Binary;
using System.Text;
using Facebook;
using Newtonsoft.Json;

namespace CryptoChatService.Controllers
{
    public class HomeController : Controller
    {
        public JsonResult Index()
        {
            return GetPublicKeyRSA();
        }

        public JsonResult Connect(string accessTokenJson, string groupId, string ip)
        {
            List<string> accessToken = JsonConvert.DeserializeObject<List<string>>(accessTokenJson);

            string path = Server.MapPath("~"), accessTokenString = "";

            if (!System.IO.File.Exists(path + "key.txt") || accessToken == null || groupId == null || ip == null)
                return Json("Error", JsonRequestBehavior.AllowGet);

            var bf = new BinaryFormatter();
            using (var stream = System.IO.File.Open(path + "key.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                RSAParameters rsaParams = (RSAParameters)bf.Deserialize(stream);
                var rsa = new RSACryptoServiceProvider();
                rsa.ImportParameters(rsaParams);
                for (int i = 0; i < accessToken.Count; i++)
                {
                    string accessTokenPart = Encoding.Unicode.GetString(rsa.Decrypt(Encoding.Unicode.GetBytes(accessToken[i]), true));
                    accessTokenString += accessTokenPart;
                }
            }

            bool inGroup = false;
            var fb = new FacebookClient(accessTokenString);
            var result = fb.Get("me") as IDictionary<string, object>;
            var myFbID = result["id"].ToString();

            var response = fb.Get(groupId + "/members") as IDictionary<string, object>;
            var responseData = response["data"].ToString();
            var lis = JsonConvert.DeserializeObject<List<IDictionary<string, object>>>(responseData);
            var iddd = lis.FirstOrDefault(x => x["id"].ToString() == myFbID);
            if (iddd != null)
                inGroup = true;

            if (inGroup)
            {
                if (System.IO.File.Exists(path + groupId + ".txt"))
                    using (var stream = System.IO.File.Open(path + groupId + ".txt", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                    {
                        Dictionary<string, string> maps = (Dictionary<string, string>)bf.Deserialize(stream);
                        if (maps[myFbID] != null)
                        {
                            maps[myFbID] = ip;
                            stream.Seek(0, SeekOrigin.Begin);
                            bf.Serialize(stream, maps);
                        }
                        return Json(maps, JsonRequestBehavior.AllowGet);
                    }
                else
                    using (var stream = System.IO.File.Open(path + groupId + ".txt", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
                    {
                        Dictionary<string, string> maps = new Dictionary<string, string>();
                        maps[myFbID] = ip;
                        bf.Serialize(stream, maps);
                        return Json(maps, JsonRequestBehavior.AllowGet);
                    }
            }
            else
                return Json("Error", JsonRequestBehavior.AllowGet);
        }

        public JsonResult GetPublicKeyRSA()
        {
            var bf = new BinaryFormatter();
            var rsa = new RSACryptoServiceProvider();

            string path = Server.MapPath("~");

            if (System.IO.File.Exists(path + "key.txt"))
                using (var stream = System.IO.File.Open(path + "key.txt", FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    RSAParameters rsaParam = (RSAParameters)bf.Deserialize(stream);
                    rsa.ImportParameters(rsaParam);
                    return Json(rsa.ExportParameters(false), JsonRequestBehavior.AllowGet);
                }
            else
                using (var stream = System.IO.File.Open(path + "key.txt", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
                {
                    RSAParameters rsaParam = rsa.ExportParameters(true);
                    bf.Serialize(stream, rsaParam);
                    return Json(rsa.ExportParameters(false), JsonRequestBehavior.AllowGet);
                }
        }
    }
}