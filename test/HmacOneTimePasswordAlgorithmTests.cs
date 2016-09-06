namespace Tests
{
    using RadicalResearch.Security.OneTimePassword;
    using System;
    using Xunit;

    public class HmacOneTimePasswordAlgorithmTests
    {
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
        public void ValidatingValidTokenFor(int iteration, string token) 
        {
            string secret = "12345678901234567890";
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc).AddSeconds(iteration * 30);
            var hmacOneTimePasswordAlgorithm = new HmacOneTimePasswordAlgorithm(secret, 0, () => epoch);
            Assert.True(hmacOneTimePasswordAlgorithm.IsValid(token), "it should pass validation");
        }

        [Fact]
        public void ValidatingInvalidToken()
        {
            string secret = "12345678901234567890";
            var epoch = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            var hmacOneTimePasswordAlgorithm = new HmacOneTimePasswordAlgorithm(secret, 0, () => epoch);
            Assert.False(hmacOneTimePasswordAlgorithm.IsValid("755225"), "it should fail validation");
        }
    }
}
