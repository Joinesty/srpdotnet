﻿using System;
using System.Text;
using SRPDotNet.Helpers;

namespace SRPDotNet.Parameters
{
    public class Bit1536 : SRPParameter
    {
        static readonly byte[] _hexaPrime = ("9DEF3CAF B939277A B1F12A86 17A47BBB DBA51DF4 99AC4C80 BEEEA961" +
                                            "4B19CC4D 5F4F5F55 6E27CBDE 51C6A94B E4607A29 1558903B A0D0F843" +
                                            "80B655BB 9A22E8DC DF028A7C EC67F0D0 8134B1C8 B9798914 9B609E0B" +
                                            "E3BAB63D 47548381 DBC5B1FC 764E3F4B 53DD9DA1 158BFD3E 2B9C8CF5" +
                                            "6EDF0195 39349627 DB2FD53D 24B7C486 65772E43 7D6C7F8C E442734A" +
                                            "F7CCB7AE 837C264A E3A9BEB8 7F8A2FE9 B8B5292E 5A021FFF 5E91479E" +
                                             "8CE7A28C 2442C6F3 15180F93 499A234D CF76E3FE D135F9BB").StringToByteArray();
                
        static readonly byte[] _generator = new byte[] { 2 };


        public Bit1536() : base(_hexaPrime, _generator, 1536) {}
    }
}