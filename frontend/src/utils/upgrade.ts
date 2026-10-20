/** Plain-language reason for a failed check (codes come from the server). */
export function describeCheckFailure(code: string | null): string {
  switch (code) {
    case 'network': return "the release server could not be reached (check this server's DNS, firewall and https_proxy)"
    case 'timeout': return 'the release server did not answer in time'
    case 'too_large': case 'truncated': case 'bad_json': case 'bad_response': return 'the release server sent an unusable answer'
    case 'redirect_refused': return 'the release server redirected to a host that is not allowed'
    case 'bad_url': return 'the configured release URL is not valid (it must be https://)'
    case 'http_403': case 'http_429': return 'the release server is rate limiting this address'
    default: return code ? `the release server answered with an error (${code})` : 'unknown reason'
  }
}
