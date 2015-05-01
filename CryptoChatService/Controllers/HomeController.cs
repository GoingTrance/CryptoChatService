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
    public static class myrsa
    {
        public static RSACryptoServiceProvider rsa;
        static myrsa()
        {
            rsa = new RSACryptoServiceProvider();
        }        
    }

    [Serializable]
    public struct RSAParameters2
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
        public JsonResult Index()
        {
            return GetPublicKeyRSA();
        }

        [HttpPost]
        public void Connect()
        {
            Stream inputStream = Request.InputStream;
            var bf = new BinaryFormatter();

            byte[] accessTokenBytes128 = (byte[])bf.Deserialize(inputStream);
            string groupId = (string)bf.Deserialize(inputStream);
            string ip = (string)bf.Deserialize(inputStream);

            string path = Server.MapPath("~"), accessTokenString = "";

            if (!System.IO.File.Exists(path + "key.txt") || accessTokenBytes128 == null || groupId == null || ip == null)
                return;

            using (var stream = System.IO.File.Open(path + "key.txt", FileMode.OpenOrCreate, FileAccess.ReadWrite, FileShare.ReadWrite))
            {
                RSAParameters2 rsaParam2 = (RSAParameters2)bf.Deserialize(stream);
                RSAParameters rsaParam = new RSAParameters();
                rsaParam.D = rsaParam2.D;
                rsaParam.DP = rsaParam2.DP;
                rsaParam.DQ = rsaParam2.DQ;
                rsaParam.Exponent = rsaParam2.Exponent;
                rsaParam.InverseQ = rsaParam2.InverseQ;
                rsaParam.Modulus = rsaParam2.Modulus;
                rsaParam.P = rsaParam2.P;
                rsaParam.Q = rsaParam2.Q;

                myrsa.rsa.ImportParameters(rsaParam);

                for (int i = 0; i < accessTokenBytes128.Length / 128; i++)
                {
                    byte[] encryptedPart = new byte[128];
                    for (int y = 0; y < 128; y++)
                        encryptedPart[y] = accessTokenBytes128[i*128 + y];

                    string accessTokenPart = Encoding.ASCII.GetString(myrsa.rsa.Decrypt(encryptedPart, true));
                    accessTokenString += accessTokenPart;
                }
            }

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

                if (System.IO.File.Exists(path + groupId + ".txt"))
                    using (var stream = System.IO.File.Open(path + groupId + ".txt", FileMode.Open, FileAccess.ReadWrite, FileShare.ReadWrite))
                    {
                        Dictionary<string, string> maps = (Dictionary<string, string>)bf.Deserialize(stream);
                        if (maps.ContainsKey(myFbID))
                            maps[myFbID] = ip;
                        else
                            maps.Add(myFbID, ip);
                        stream.Seek(0, SeekOrigin.Begin);
                        bf.Serialize(stream, maps);
                        bf.Serialize(outStream, maps);
                    }
                else
                    using (var stream = System.IO.File.Open(path + groupId + ".txt", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
                    {
                        Dictionary<string, string> maps = new Dictionary<string, string>();
                        maps.Add(myFbID, ip);
                        bf.Serialize(stream, maps);
                        bf.Serialize(outStream, maps);
                    }
            }            
        }

        public JsonResult GetPublicKeyRSA()
        {
            var bf = new BinaryFormatter();
            string path = Server.MapPath("~");

            if (System.IO.File.Exists(path + "key.txt"))
                using (var stream = System.IO.File.Open(path + "key.txt", FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
                {
                    RSAParameters2 rsaParam2 = (RSAParameters2)bf.Deserialize(stream);
                    RSAParameters rsaParam = new RSAParameters();
                    rsaParam.D = rsaParam2.D;
                    rsaParam.DP = rsaParam2.DP;
                    rsaParam.DQ = rsaParam2.DQ;
                    rsaParam.Exponent = rsaParam2.Exponent;
                    rsaParam.InverseQ = rsaParam2.InverseQ;
                    rsaParam.Modulus = rsaParam2.Modulus;
                    rsaParam.P = rsaParam2.P;
                    rsaParam.Q = rsaParam2.Q;
                    myrsa.rsa.ImportParameters(rsaParam);

                    return Json(myrsa.rsa.ExportParameters(false), JsonRequestBehavior.AllowGet);
                }
            else
                using (var stream = System.IO.File.Open(path + "key.txt", FileMode.CreateNew, FileAccess.ReadWrite, FileShare.ReadWrite))
                {
                    RSAParameters rsaParam = myrsa.rsa.ExportParameters(true);
                    RSAParameters2 rsaParam2 = new RSAParameters2();
                    rsaParam2.D = rsaParam.D;
                    rsaParam2.DP = rsaParam.DP;
                    rsaParam2.DQ = rsaParam.DQ;
                    rsaParam2.Exponent = rsaParam.Exponent;
                    rsaParam2.InverseQ = rsaParam.InverseQ;
                    rsaParam2.Modulus = rsaParam.Modulus;
                    rsaParam2.P = rsaParam.P;
                    rsaParam2.Q = rsaParam.Q;
                    bf.Serialize(stream, rsaParam2);

                    return Json(myrsa.rsa.ExportParameters(false), JsonRequestBehavior.AllowGet);
                }
        }
    }
}