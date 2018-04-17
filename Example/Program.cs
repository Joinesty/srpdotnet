﻿using System;
using SRPDotNet.Parameters;
using SRPDotNet.Models;
using System.Security.Cryptography;
using SRPDotNet;
using SRPDotNet.Helpers;

namespace Example
{
    class Program
    {
        static void Main(string[] args)
        {
            StartClient();
            Console.WriteLine("done...");
        }

        static void StartClient()
        {
            
            var username = "johndoe";
            var password = "password";
            var hash = SHA256.Create();
            var parameter = new Bit2048();
            var srp = new SecureRemoteProtocol(hash, parameter);
            var privateKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();
            var serverKey = SecureRemoteProtocol.GetRandomNumber().ToBytes();

            var verificationKey1 = srp.CreateVerificationKey(username, password);

            var user1 = new SRPUser(username, password, hash, parameter);
            var a = user1.GetEphemeralSecret();
            var authentication1 = user1.StartAuthentication();

            var svr1 = new SRPVerifier(hash, parameter, verificationKey1,
                                    authentication1.PublicKey);

            var b = svr1.GetEphemeralSecret();
            var challenge1 = svr1.GetChallenge();
            var session1 = user1.ProcessChallenge(challenge1);

            var hamk = svr1.VerifiySession(session1);



        }
    }
}
