using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using SRPDotNet.Parameters;
using SRPDotNet;
using System.Linq;
using SRPDotNet.Models;
using System.Numerics;
using SRPDotNet.Helpers;


namespace SRPDotNet.Tests
{
    [TestClass]
    public class SRPTests
    {

        [TestMethod]
        public void TestConversions()
        {
            var v1 = SecureRemoteProtocol.GetRandomNumber();
            var v1int = v1.ToBytes();
            var int2 = v1int;
            var v2 = int2.ToBigInteger();

            Assert.AreEqual(v1, v2);
        }


        [TestMethod]
        public void ShouldAuthenticateSameUserTwice()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit4096();
            var user1 = new User(username, password, hash, parameter, null);

            var a = user1.GetEphemeralSecret();
            var authentication1 = user1.StartAuthentication();

            var user2 = new User(username, password, hash, parameter, a);
            var user2Ephemeral = user2.GetEphemeralSecret();
            Assert.IsTrue(a.CheckEquals(user2Ephemeral));
        }


        [TestMethod]
        public void ShouldAuthenticateOnTheServer()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = SHA256.Create();
            var parameter = new Bit2048();
            var srp = new SecureRemoteProtocol(hash, parameter);
            var privateKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var serverKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var verificationKey1 = srp.CreateVerificationKey(username, password);

            var user1 = new User(username, password, hash, parameter, null);
           
            var a = user1.GetEphemeralSecret();

            var authentication1 = user1.StartAuthentication();

            var svr1 = new Verifier(hash, parameter, verificationKey1, privateKey, serverKey);
            var challenge1 = svr1.GetChallenge();
            var session1 = user1.ProcessChallenge(challenge1);
            var hamk1 = svr1.VerifiySession(session1);

            user1.VerifySession(hamk1);

            Assert.IsTrue(svr1.IsAuthenticated);
        }

        [TestMethod]
        public void ShouldAuthenticateTheSameUserOnTheServer()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit4096();
            var srp = new SecureRemoteProtocol(hash, parameter);
            var privateKey = SecureRemoteProtocol.GetRandomNumber().ToByteArray();
            var serverKey = SecureRemoteProtocol.GetRandomNumber().ToByteArray();

            var verificationKey1 = srp.CreateVerificationKey(username, password);

            var user1 = new User(username, password, hash, parameter, privateKey);
           
            var authentication1 = user1.StartAuthentication();

            var user2 = new User(username, password, hash, parameter, privateKey);
            var verificationKey2 = srp.CreateVerificationKey(username, password);
            var authentication2 = user2.StartAuthentication();

            // Make sure a recreated User does all the same appropriate things
            Assert.AreEqual(authentication2.Username, authentication1.Username);
            Assert.IsTrue(authentication2.PublicKey.SequenceEqual(authentication1.PublicKey));

            var svr1 = new Verifier(hash, parameter, verificationKey1, privateKey, serverKey);
            var challenge1 = svr1.GetChallenge();
            var session1 = user1.ProcessChallenge(challenge1);
            var hamk1 = svr1.VerifiySession(session1);

            //Make sure that a recreated Verifier will authenticate appropriately
            var svr2 = new Verifier(hash, parameter, verificationKey2, privateKey, serverKey);
            var challenge2 = svr2.GetChallenge();
            var session2 = user2.ProcessChallenge(challenge2);
            var hamk2 = svr2.VerifiySession(session2);

            Assert.IsTrue(session1.Key.SequenceEqual(session2.Key));
            Assert.IsTrue(hamk1.Key.SequenceEqual(hamk2.Key));

            user1.VerifySession(hamk1);
            user2.VerifySession(hamk2);

            Assert.IsTrue(svr1.IsAuthenticated);
            //Assert.IsTrue(svr2.IsAuthenticated);

        }
    }
}
