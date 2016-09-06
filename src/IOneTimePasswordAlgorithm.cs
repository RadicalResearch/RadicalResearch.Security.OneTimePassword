using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace RadicalResearch.Security.OneTimePassword
{
    public interface IOneTimePasswordAlgorithm
    {
        bool IsValid(string token);
    }
}
