<script lang="ts">
  import { onMount } from 'svelte';
  import InputPanel from './InputPanel.svelte';
  import ResultsPanel from './ResultsPanel.svelte';
  import CorrectedOutput from './CorrectedOutput.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import FaqSection from './FaqSection.svelte';
  import AdoptionBar from './AdoptionBar.svelte';
  import { parse } from '../lib/parser';
  import { validate } from '../lib/validator';
  import { generateCorrectedOutput } from '../lib/corrector';
  import { fetchSecurityTxt } from '../lib/fetchProxy';
  import type { ValidationResult, ParsedLine, Finding, FetchMetadata, PgpInfo } from '../lib/types';
  import type { FetchProxyError } from '../lib/fetchProxy';

  let validationResult: ValidationResult | null = null;
  let correctedText = '';
  let rawContent = '';
  let parsedLines: ParsedLine[] = [];
  let findings: Finding[] = [];
  let loading = false;
  let errorMessage = '';
  let mode: 'paste' | 'url' | 'generate' = 'paste';

  onMount(() => {
    document.title = 'security.txt Validator — Validate, Generate & Fix per RFC 9116';
    const meta = document.querySelector('meta[name="description"]');
    if (meta) meta.setAttribute('content', 'Free online tool to validate, generate, and auto-correct security.txt files per RFC 9116.');
  });

  function runValidation(content: string, fetchMeta?: FetchMetadata) {
    const result = parse(content, { withPgp: true });
    parsedLines = result.lines;
    const pgp: PgpInfo = result.pgp;
    validationResult = validate(parsedLines, fetchMeta, pgp);
    findings = validationResult.findings;
    correctedText = generateCorrectedOutput(parsedLines, findings);
  }

  function clearResults() {
    validationResult = null;
    correctedText = '';
    rawContent = '';
    parsedLines = [];
    findings = [];
    errorMessage = '';
  }

  async function handleValidate(event: CustomEvent<{ mode: 'paste' | 'url' | 'generate'; content: string; domain: string }>) {
    const { mode: inputMode, content, domain } = event.detail;
    mode = inputMode;
    clearResults();

    if (inputMode === 'paste' || inputMode === 'generate') {
      try {
        runValidation(content);
      } catch {
        errorMessage = 'An unexpected error occurred during validation. Please try again.';
      }
      return;
    }

    loading = true;
    try {
      const result = await fetchSecurityTxt(domain);
      rawContent = result.content;
      runValidation(result.content, result.metadata);
    } catch (err: unknown) {
      const proxyErr = err as FetchProxyError;
      errorMessage = mapProxyError(proxyErr);
    } finally {
      loading = false;
    }
  }

  function mapProxyError(err: FetchProxyError): string {
    switch (err.error) {
      case 'timeout': return 'The remote server did not respond within 10 seconds.';
      case 'size_limit': return 'The remote file exceeds the 100 KB size limit.';
      case 'dns_failure': return 'Could not resolve the domain. Please check the spelling.';
      case 'ssrf_blocked': return 'The provided URL targets a restricted address.';
      case 'invalid_content_type': return 'The remote server did not return a text/plain response.';
      case 'not_found': return 'No security.txt file was found on the remote server.';
      case 'too_many_redirects': return 'Too many redirects while fetching the file.';
      case 'http_error': return err.httpStatus ? `The remote server returned HTTP ${err.httpStatus}.` : 'The remote server returned an error.';
      case 'network_error': return 'Unable to reach the validation service. Please try again later.';
      default: return err.message || 'An unexpected error occurred.';
    }
  }
</script>

<div class="sectxt-page">
  <div class="hero">
    <h1 class="title">security.txt validator</h1>
    <p class="subtitle">Validate and fix your security.txt file against RFC 9116</p>
  </div>

  <InputPanel on:validate={handleValidate} />

  {#if loading}
    <LoadingSpinner />
  {/if}

  {#if errorMessage}
    <div class="error-banner" role="alert">
      <p>{errorMessage}</p>
    </div>
  {/if}

  {#if validationResult}
    <div class="results-area">
      <ResultsPanel result={validationResult} {mode} />
      <CorrectedOutput {correctedText} lines={parsedLines} {findings} {mode} {rawContent} />
    </div>
  {/if}

  <FaqSection />
  <AdoptionBar />

  <p class="cross-link">
    <a href="/#/">← Check your full domain security</a>
  </p>
</div>

<style>
  .sectxt-page {
    display: flex;
    flex-direction: column;
  }

  .hero {
    text-align: center;
    margin-bottom: 2rem;
  }

  .title {
    font-size: 1.5rem;
    font-weight: 700;
    color: var(--color-text);
    letter-spacing: -0.02em;
  }

  .subtitle {
    color: var(--color-text-secondary);
    font-size: 0.875rem;
    margin-top: 0.35rem;
  }

  .error-banner {
    background: rgba(255, 77, 106, 0.1);
    border: 1px solid var(--color-error);
    border-radius: var(--radius);
    padding: 0.75rem 1rem;
    margin-top: 1rem;
    color: var(--color-error);
    font-size: 0.875rem;
  }

  .results-area {
    display: flex;
    flex-direction: column;
    gap: 1rem;
    margin-top: 1rem;
  }

  .cross-link {
    margin-top: 2rem;
    text-align: center;
    font-size: 0.85rem;
  }
</style>
