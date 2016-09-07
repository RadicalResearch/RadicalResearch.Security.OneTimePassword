namespace RadicalResearch.Security.OneTimePassword.Tests
{
    using System;
    using Xunit;

    public class HmacOneTimePasswordAlgorithmTests
    {
        private const string Secret = "12345678901234567890";

        // Test values from https://tools.ietf.org/html/rfc4226
        [Theory]
        [InlineData(0, "755224")]
        [InlineData(1, "287082")]
        [InlineData(2, "359152")]
        [InlineData(3, "969429")]
        [InlineData(4, "338314")]
        [InlineData(5, "254676")]
        [InlineData(6, "287922")]
        [InlineData(7, "162583")]
        [InlineData(8, "399871")]
        [InlineData(9, "520489")]
        public void ValidatingValidPasswordFor(int iteration, string password) 
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(iteration * 30);
            var hmacOneTimePasswordAlgorithm = new HmacOneTimePasswordAlgorithm(0, () => epoch);
            Assert.True(hmacOneTimePasswordAlgorithm.IsValid(Secret, password), "it should pass validation");
        }

        [Fact]
        public void ValidatingInvalidPassword()
        {
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var hmacOneTimePasswordAlgorithm = new HmacOneTimePasswordAlgorithm(0, () => epoch);
            Assert.False(hmacOneTimePasswordAlgorithm.IsValid(Secret, "invalid password"), "it should fail validation");
        }

        [Theory]
        [InlineData(0, "338314")] // -1
        [InlineData(0, "287922")] // +1
        [InlineData(1, "969429")] // -2
        [InlineData(1, "162583")] // +2
        [InlineData(2, "359152")] // -3
        [InlineData(2, "399871")] // +3
        public void ValidatingPasswordOutsideIterationVariance(int variance, string password)
        {
            var iteration = 5;
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(iteration * 30);

            var hmacOneTimePasswordAlgorithm = new HmacOneTimePasswordAlgorithm(variance, () => epoch);
            Assert.False(hmacOneTimePasswordAlgorithm.IsValid(Secret, password), "it should fail validation");
        }

        [Theory]
        [InlineData(1, "338314")] // -1
        [InlineData(1, "254676")] //  0
        [InlineData(1, "287922")] // +1
        [InlineData(2, "969429")] // -2
        [InlineData(2, "338314")] // -1
        [InlineData(2, "254676")] //  0
        [InlineData(2, "287922")] // +1
        [InlineData(2, "162583")] // +2
        public void ValidatingPasswordInsideIterationVariance(int variance, string password)
        {
            var iteration = 5;
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                .AddSeconds(iteration * 30);

            var hmacOneTimePasswordAlgorithm = new HmacOneTimePasswordAlgorithm(variance, () => epoch);
            Assert.True(hmacOneTimePasswordAlgorithm.IsValid(Secret, password), "it should pass validation");
        }
    }
}
