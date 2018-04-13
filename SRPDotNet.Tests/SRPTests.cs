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
        public void ShouldWork()
        {
            var username = "johndoe";
            var password = "password";
            var hash = new HMACSHA256();
            var parameter = new Bit2048();
            var srp = new SecureRemoteProtocol(hash, parameter);
            var privateKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var serverKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();

            var verificationKey1 = srp.CreateVerificationKey(username, password);

            var user1 = new SRPUser(username, password, hash, parameter);
            var authentication1 = user1.StartAuthentication();

            var svr1 = new SRPVerifier(hash, parameter, verificationKey1,
                                    authentication1.PublicKey);

            var b = svr1.GetEphemeralSecret();
            var challenge1 = svr1.GetChallenge();
            var session1 = user1.ProcessChallenge(challenge1);

            var hamk = svr1.VerifiySession(session1);

            Assert.IsNotNull(hamk);

        }



        [TestMethod]
        public void ShouldAuthenticateSameUserTwice()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit2048();
            var user1 = new SRPUser(username, password, hash, parameter);

            var a = user1.GetEphemeralSecret();
            var authentication1 = user1.StartAuthentication();

            var user2 = new SRPUser(username, password, hash, parameter);
            var user2Ephemeral = user2.GetEphemeralSecret();
            Assert.IsTrue(a.CheckEquals(user2Ephemeral));

            var authentication2 = user2.StartAuthentication();

            Assert.AreEqual(authentication1.Username, authentication2.Username);
            Assert.IsTrue(authentication1.PublicKey.CheckEquals(authentication2.PublicKey));
        }



        [TestMethod]
        public void ShouldAuthenticateOnTheServer()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit2048();
            var srp = new SecureRemoteProtocol(hash, parameter);
            var privateKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var serverKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var verificationKey1 = srp.CreateVerificationKey(username, password);

            var user1 = new SRPUser(username, password, hash, parameter);
            var a = user1.GetEphemeralSecret();
            var authentication1 = user1.StartAuthentication();


            var user2 = new SRPUser(username, password, hash, parameter);
            var user2Ephemeral = user2.GetEphemeralSecret();
            var authentication2 = user2.StartAuthentication();

            Assert.IsTrue(authentication1.PublicKey.CheckEquals(authentication2.PublicKey));

            var svr1 = new SRPVerifier(hash, parameter, verificationKey1, 
                                       authentication1.PublicKey);
            
            var b = svr1.GetEphemeralSecret();
            var challenge1 = svr1.GetChallenge();
            var session1 = user1.ProcessChallenge(challenge1);
            var session2 = user2.ProcessChallenge(challenge1);
            Assert.IsTrue(session1.Key.CheckEquals(session2.Key));

        }




        [TestMethod]
        public void ShouldAuthenticateTheSameUserOnTheServer()
        {
            var username = "johndoe";
            var password = "password1234";
            var hash = new HMACSHA256();
            var parameter = new Bit2048();
            var srp = new SecureRemoteProtocol(hash, parameter);
            var privateKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var serverKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var verificationKey1 = srp.CreateVerificationKey(username, password);

            var user1 = new SRPUser(username, password, hash, parameter);
            var a = user1.GetEphemeralSecret();
            var authentication1 = user1.StartAuthentication();


            var user2 = new SRPUser(username, password, hash, parameter);
            var user2Ephemeral = user2.GetEphemeralSecret();
            var authentication2 = user2.StartAuthentication();

            Assert.IsTrue(authentication1.PublicKey.CheckEquals(authentication2.PublicKey));

            var svr1 = new SRPVerifier(hash, parameter, verificationKey1,
                                    authentication1.PublicKey);

            var b = svr1.GetEphemeralSecret();
            var challenge1 = svr1.GetChallenge();
            var session1 = user1.ProcessChallenge(challenge1);
            var session2 = user2.ProcessChallenge(challenge1);
            Assert.IsTrue(session1.Key.CheckEquals(session2.Key));

            var hamk = svr1.VerifiySession(session1);


            var svr2 = new SRPVerifier(hash, parameter, verificationKey1,
                                    authentication1.PublicKey);
            
            Assert.IsTrue(b.CheckEquals(svr2.GetEphemeralSecret()));

            var hamk2 = svr2.VerifiySession(session1);

            Assert.IsTrue(hamk.Key.CheckEquals(hamk2.Key));


        }

    }
}
