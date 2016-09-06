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
    public class HmacOneTimePasswordAlgorithm: IOneTimePasswordAlgorithm, IDisposable
    {
        private static readonly DateTime UnixEpoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);

        private readonly HashAlgorithm hashAlgorithm;

        private Func<DateTime> utcNowFunc;

        private int iterationVariance;

        public HmacOneTimePasswordAlgorithm(string secret, int iterationVariance, Func<DateTime> utcNowFunc)
        {
            this.utcNowFunc = utcNowFunc;
            this.iterationVariance = iterationVariance;
            var secretBytes = Encoding.ASCII.GetBytes(secret);
            this.hashAlgorithm = new HMACSHA1(secretBytes);
        }

        public void Dispose()
        {
            hashAlgorithm.Dispose();
        }

        private long GetIterationNumber()
        {
            return (long)(this.utcNowFunc() - UnixEpoch).TotalSeconds / 30;
        }

        private string GenerateToken(long iterationNumber)
        {
            const int TokenLength = 6;
            var counter = BitConverter.GetBytes(iterationNumber);
            if (BitConverter.IsLittleEndian)
            {
                Array.Reverse(counter);
            }

            byte[] hash = this.hashAlgorithm.ComputeHash(counter);
            var offset = hash[hash.Length - 1] & 0xf;

            var bytes =
                ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);

            var password = bytes % (int)Math.Pow(10, TokenLength);

            var formatString = new string('0', TokenLength);
            return password.ToString(formatString, NumberFormatInfo.InvariantInfo);
        }

        /// <summary>
        /// Validates the specified token.
        /// </summary>
        /// <param name="token">The token.</param>
        /// <param name="iterationVariance">acceptable iterations either side of the current iteration</param>
        /// <returns><c>True</c> if the token is valid; otherwise <c>False</c>.</returns>
        public bool IsValid(string token)
        {
            var iterationNumber = this.GetIterationNumber();

            return Enumerable
                .Range(-this.iterationVariance, (this.iterationVariance * 2) + 1)
                .Any(i => this.GenerateToken(iterationNumber + i).Equals(token));
        }
    }
}
