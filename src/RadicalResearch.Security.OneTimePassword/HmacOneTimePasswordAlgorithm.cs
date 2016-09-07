using System.Net.Http;

namespace RadicalResearch.Security.OneTimePassword
{
    using System;
    using System.Globalization;
    using System.Linq;
    using System.Security.Cryptography;
    using System.Text;

    /// <summary>
    /// RFC4226 HOTP Algorithm
    /// </summary>
    public class HmacOneTimePasswordAlgorithm: IOneTimePasswordAlgorithm
    {
        private static readonly DateTime Epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly Func<DateTime> _utcNowFunc;

        private readonly int _iterationVariance;

        public HmacOneTimePasswordAlgorithm() : this(1, () => DateTime.UtcNow)
        {
        }

        public HmacOneTimePasswordAlgorithm(int iterationVariance, Func<DateTime> utcNowFunc)
        {
            _utcNowFunc = utcNowFunc;
            _iterationVariance = iterationVariance;
        }

        private long GetIterationNumber()
        {
            return (long)(_utcNowFunc() - Epoch).TotalSeconds / 30;
        }

        private static string GenerateToken(HashAlgorithm hashAlgorithm, long iterationNumber)
        {
            const int tokenLength = 6;

            var counter = BitConverter.GetBytes(iterationNumber);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            var hash = hashAlgorithm.ComputeHash(counter);
            var offset = hash[hash.Length - 1] & 0xf;

            var bytes =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

            var password = bytes % (int)Math.Pow(10, tokenLength);

            var formatString = new string('0', tokenLength);
            return password.ToString(formatString, NumberFormatInfo.InvariantInfo);
        }

        /// <summary>
        /// Validates a one time password provided by the user.
        /// </summary>
        /// <param name="secret">Shared secret</param>
        /// <param name="password">Password </param>
        /// <returns><c>true</c> if the password is valid; otherwise <c>false</c></returns>
        public bool IsValid(string secret, string password)
        {
            if (string.IsNullOrEmpty(secret))
            {
                throw new ArgumentNullException(nameof(secret));
            }

            var secretBytes = Encoding.ASCII.GetBytes(secret);
            return IsValid(secretBytes, password);
        }

        /// <summary>
        /// Validates a one time password provided by the user.
        /// </summary>
        /// <param name="secret">Shared secret</param>
        /// <param name="password">Password </param>
        /// <returns><c>true</c> if the password is valid; otherwise <c>false</c></returns>
        public bool IsValid(byte[] secret, string password)
        {
            if (string.IsNullOrEmpty(password))
            {
                throw new ArgumentNullException(nameof(password));
            }

            var iterationNumber = GetIterationNumber();
            using (var hashAlgorithm = new HMACSHA1(secret))
            {
                return Enumerable
                    .Range(-_iterationVariance, (_iterationVariance * 2) + 1)
                    .Any(i => GenerateToken(hashAlgorithm, iterationNumber + i).Equals(password));
            }
        }
    }
}
