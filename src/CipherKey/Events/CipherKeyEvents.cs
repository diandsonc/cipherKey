namespace CipherKey.Events
{
    /// <summary>
    /// Encapsulates events related to CipherKey authentication.
    /// </summary>
    public class CipherKeyEvents
    {
        /// <summary>
        /// A delegate assigned to this property will be invoked just before validating the API key.
        /// </summary>
        /// <remarks>
        /// To proceed with authentication, you must provide a delegate for this property.
        /// Within your delegate, you should either call <c>context.ValidationSucceeded()</c>,
        /// which handles construction of the authentication principal assigned to <c>context.Principal</c>,
        /// and then call <c>context.Success()</c>.
        /// </remarks>
        public Func<ValidateKeyContext, Task>? OnValidateKey { get; set; }

        /// <summary>
        /// Invoked when validating the API key.
        /// </summary>
        /// <param name="context">The validation context.</param>
        /// <returns>A <see cref="Task"/> representing the asynchronous operation.</returns>
        public virtual Task ValidateKeyAsync(ValidateKeyContext context) =>
            OnValidateKey is null ? Task.CompletedTask : OnValidateKey(context);
    }
}
