using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using System.Security.Cryptography;
using SRPDotNet.Parameters;
using SRPDotNet;
using System.Linq;
using SRPDotNet.Models;

namespace SRPDotNet.Tests
{
    [TestClass]
    public class SRPTests
    {

        [TestMethod]
        public void ShouldAuthenticateSameUserTwice()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit4096();
            var privateKey = SecureRemoteProtocol.GetRandomNumber();

            var user1 = new User(username, password, hash, parameter, privateKey);
            var verificationKey1 = user1.CreateVerificationKey();
            var authentication1 = user1.StartAuthentication();

            var user2 = new User(username, password, hash, parameter, privateKey);
            var verificationKey2 = user2.CreateVerificationKey();
            var authentication2 = user2.StartAuthentication();

            // Make sure a recreated User does all the same appropriate things
            Assert.AreEqual(authentication2.Username, authentication1.Username);
            Assert.IsTrue(authentication2.PublicKey.SequenceEqual(authentication1.PublicKey));
        }

        [TestMethod]
        public void ShouldAuthenticateOnTheServer()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit4096();
            var privateKey = SecureRemoteProtocol.GetRandomNumber();
            var serverKey = SecureRemoteProtocol.GetRandomNumber();

            var user1 = new User(username, password, hash, parameter, privateKey);
            var verificationKey1 = user1.CreateVerificationKey();
            var authentication1 = user1.StartAuthentication();

            var user2 = new User(username, password, hash, parameter, privateKey);
            var verificationKey2 = user2.CreateVerificationKey();
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
            Assert.IsTrue(svr2.IsAuthenticated);

        }
    }
}
