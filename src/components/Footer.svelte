<footer class="footer">
  <nav class="footer-links" aria-label="Footer navigation">
    <a href="/#/pricing">Pricing</a>
    <a href="/#/terms">Terms of Service</a>
    <a href="/#/privacy">Privacy Policy</a>
    <a href="/#/refund">Refund Policy</a>
    <a href="/#/contact">Contact</a>
  </nav>
  <p class="footer-copy">&copy; {new Date().getFullYear()} Domain Security Checker</p>
</footer>

<style>
  .footer {
    border-top: 1px solid var(--color-border);
    margin-top: 2rem;
    padding: 1rem 0 0;
    text-align: center;
  }

  .footer-links {
    display: flex;
    flex-wrap: wrap;
    justify-content: center;
    gap: 0.75rem;
    margin-bottom: 0.5rem;
  }

  .footer-links a {
    font-size: 0.75rem;
    color: var(--color-text-secondary);
    text-decoration: none;
    transition: color var(--transition);
  }

  .footer-links a:hover {
    color: var(--color-text);
  }

  .footer-copy {
    font-size: 0.7rem;
    color: var(--color-text-secondary);
  }
</style>
