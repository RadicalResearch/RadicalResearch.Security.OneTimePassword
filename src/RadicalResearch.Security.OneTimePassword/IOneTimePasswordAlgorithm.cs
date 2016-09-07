namespace RadicalResearch.Security.OneTimePassword
{
    public interface IOneTimePasswordAlgorithm
    {
        /// <summary>
        /// Validates a one time password provided by the user.
        /// </summary>
        /// <param name="secret">Shared secret</param>
        /// <param name="password">Password </param>
        /// <returns>True if the password is valid; otherwise false</returns>
        bool IsValid(string secret, string password);

        /// <summary>
        /// Validates a one time password provided by the user.
        /// </summary>
        /// <param name="secret">Shared secret</param>
        /// <param name="password">Password </param>
        /// <returns><c>true</c> if the password is valid; otherwise <c>false</c></returns>
        bool IsValid(byte[] secret, string password);
    }
}
