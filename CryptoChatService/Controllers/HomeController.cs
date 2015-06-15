using Facebook;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.Serialization.Formatters.Binary;
using System.Security.Cryptography;
using System.Text;
using System.Web.Mvc;

namespace CryptoChatService.Controllers
{
    public static class MyRSAProvider
    {
        public static RSACryptoServiceProvider RSAWrapper;
        static MyRSAProvider()
        {
            RSAWrapper = new RSACryptoServiceProvider();
        }        
    }

    [Serializable]
    public struct SerializableRSAParameters
    {
        public byte[] D;
        public byte[] DP;
        public byte[] DQ;
        public byte[] Exponent;
        public byte[] InverseQ;
        public byte[] Modulus;
        public byte[] P;
        public byte[] Q;
    }

    public class HomeController : Controller
    {
        public const string keyPath = "key.txt";

        public JsonResult Index()
        {
            return GetPublicKeyRSA();
        }

        [HttpPost]
        public void Connect()
        {
            Stream inputStream = Request.InputStream;
            var binFormatter = new BinaryFormatter();

            byte[] accessTokenBytes128 = (byte[])binFormatter.Deserialize(inputStream);
            string groupId = (string)binFormatter.Deserialize(inputStream);
            string ip = (string)binFormatter.Deserialize(inputStream);

            string serverPath = Server.MapPath("~"), accessTokenString = "";

            if (!System.IO.File.Exists(serverPath + keyPath) || accessTokenBytes128 == null || groupId == null || ip == null)
                return;

            using (var stream = System.IO.File.Open(serverPath + keyPath, FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                var myRSAParams = (SerializableRSAParameters)binFormatter.Deserialize(stream);

                var rsaParams = new RSAParameters();
                rsaParams.D = myRSAParams.D;
                rsaParams.DP = myRSAParams.DP;
                rsaParams.DQ = myRSAParams.DQ;
                rsaParams.Exponent = myRSAParams.Exponent;
                rsaParams.InverseQ = myRSAParams.InverseQ;
                rsaParams.Modulus = myRSAParams.Modulus;
                rsaParams.P = myRSAParams.P;
                rsaParams.Q = myRSAParams.Q;

                MyRSAProvider.RSAWrapper.ImportParameters(rsaParams);                
            }

            // AT decrypt by parts
            for (int i = 0; i < accessTokenBytes128.Length / 128; i++)
            {
                byte[] encryptedPart = new byte[128];
                for (int y = 0; y < 128; y++)
                    encryptedPart[y] = accessTokenBytes128[i * 128 + y];

                string accessTokenPart = Encoding.ASCII.GetString(MyRSAProvider.RSAWrapper.Decrypt(encryptedPart, true));
                accessTokenString += accessTokenPart;
            }

            // Check if member is in fb group
            bool inGroup = false;
            var fb = new FacebookClient(accessTokenString);
            var result = fb.Get("me") as IDictionary<string, object>;
            var myFbID = result["id"].ToString();

            var fbGroupMembersResponse = fb.Get(groupId + "/members") as IDictionary<string, object>;
            var fbGroupMembersResponseData = fbGroupMembersResponse["data"].ToString();
            var membersIdList = JsonConvert.DeserializeObject<List<IDictionary<string, object>>>(fbGroupMembersResponseData);
            var fbMember = membersIdList.FirstOrDefault(x => x["id"].ToString() == myFbID);
            if (fbMember != null)
                inGroup = true;

            if (inGroup)
            {
                Stream outStream = Response.OutputStream;

                if (System.IO.File.Exists(serverPath + groupId + ".txt"))
                    using (var stream = System.IO.File.Open(serverPath + groupId + ".txt", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                    {
                        Dictionary<string, string> maps = (Dictionary<string, string>)binFormatter.Deserialize(stream);
                        if (maps.ContainsKey(myFbID))
                            maps[myFbID] = ip;
                        else
                            maps.Add(myFbID, ip);
                        stream.Seek(0, SeekOrigin.Begin);
                        binFormatter.Serialize(stream, maps);
                        binFormatter.Serialize(outStream, maps);
                    }
                else
                    using (var stream = System.IO.File.Open(serverPath + groupId + ".txt", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
                    {
                        Dictionary<string, string> maps = new Dictionary<string, string>();
                        maps.Add(myFbID, ip);
                        binFormatter.Serialize(stream, maps);
                        binFormatter.Serialize(outStream, maps);
                    }
            }            
        }

        public JsonResult GetPublicKeyRSA()
        {
            var binFormatter = new BinaryFormatter();
            string path = Server.MapPath("~");

            if (System.IO.File.Exists(path + keyPath))
                using (var stream = System.IO.File.Open(path + keyPath, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    SerializableRSAParameters myRSAParams = (SerializableRSAParameters)binFormatter.Deserialize(stream);

                    var RSAParams = new RSAParameters();
                    RSAParams.D = myRSAParams.D;
                    RSAParams.DP = myRSAParams.DP;
                    RSAParams.DQ = myRSAParams.DQ;
                    RSAParams.Exponent = myRSAParams.Exponent;
                    RSAParams.InverseQ = myRSAParams.InverseQ;
                    RSAParams.Modulus = myRSAParams.Modulus;
                    RSAParams.P = myRSAParams.P;
                    RSAParams.Q = myRSAParams.Q;
                    MyRSAProvider.RSAWrapper.ImportParameters(RSAParams);

                    return Json(MyRSAProvider.RSAWrapper.ExportParameters(false), JsonRequestBehavior.AllowGet);
                }
            else
                using (var stream = System.IO.File.Open(path + keyPath, FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
                {
                    RSAParameters RSAParams = MyRSAProvider.RSAWrapper.ExportParameters(true);

                    var myRSAParams = new SerializableRSAParameters();
                    myRSAParams.D = RSAParams.D;
                    myRSAParams.DP = RSAParams.DP;
                    myRSAParams.DQ = RSAParams.DQ;
                    myRSAParams.Exponent = RSAParams.Exponent;
                    myRSAParams.InverseQ = RSAParams.InverseQ;
                    myRSAParams.Modulus = RSAParams.Modulus;
                    myRSAParams.P = RSAParams.P;
                    myRSAParams.Q = RSAParams.Q;
                    binFormatter.Serialize(stream, myRSAParams);

                    return Json(MyRSAProvider.RSAWrapper.ExportParameters(false), JsonRequestBehavior.AllowGet);
                }
        }

        public JsonResult DeleteGroup(int groupId)
        {
            try
            {
                string serverPath = Server.MapPath("~");

                if (System.IO.File.Exists(serverPath + groupId + ".txt"))
                {
                    System.IO.File.Delete(serverPath + groupId + ".txt");
                }

                return Json("OK");
            }
            catch(Exception e)
            {
                return Json(e.Message);
            }
                     
        }
    }
}