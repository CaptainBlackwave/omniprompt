export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  cookies: Record<string, string>;
}

export interface RequestOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  proxyUrl?: string;
  timeout?: number;
}

const defaultUserAgent = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36';

export async function sendRequest(
  url: string,
  options: RequestOptions = {}
): Promise<HttpResponse> {
  const method = options.method || 'GET';
  const headers = options.headers || {};
  const body = options.body;

  const requestHeaders: Record<string, string> = {
    'User-Agent': defaultUserAgent,
    ...headers,
  };

  if (!requestHeaders['Accept']) {
    requestHeaders['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8';
  }

  const fetchOptions: RequestInit = {
    method,
    headers: requestHeaders,
    redirect: 'follow',
  };

  if (body && method !== 'GET') {
    fetchOptions.body = body;
  }

  let fetchUrl = url;
  if (options.proxyUrl) {
    fetchUrl = options.proxyUrl + '?' + new URLSearchParams({ url }).toString();
  }

  const response = await fetch(fetchUrl, fetchOptions);

  const cookieHeader = response.headers.get('set-cookie') || '';
  const cookies: Record<string, string> = {};
  
  cookieHeader.split(',').forEach(cookie => {
    const [nameValue] = cookie.split(';');
    const [name, value] = nameValue.split('=');
    if (name && value) {
      cookies[name.trim()] = value.trim();
    }
  });

  const responseHeaders: Record<string, string> = {};
  response.headers.forEach((value, key) => {
    responseHeaders[key.toLowerCase()] = value;
  });

  return {
    status: response.status,
    headers: responseHeaders,
    body: await response.text(),
    cookies,
  };
}

export async function sendEvasionRequest(
  url: string,
  evasionResult: {
    modifiedPayload?: string;
    modifiedHeaders?: Record<string, string>;
    modifiedBody?: string;
    contentType?: string;
    method?: string;
  },
  proxyUrl?: string
): Promise<HttpResponse> {
  const method = evasionResult.method || 'GET';
  const headers: Record<string, string> = {
    ...evasionResult.modifiedHeaders,
  };

  if (evasionResult.contentType) {
    headers['Content-Type'] = evasionResult.contentType;
  }

  let body = evasionResult.modifiedBody;

  if (!body && evasionResult.modifiedPayload && method === 'GET') {
    try {
      const urlObj = new URL(url);
      urlObj.searchParams.set('q', evasionResult.modifiedPayload);
      return sendRequest(urlObj.toString(), { method, headers, proxyUrl });
    } catch {
      return sendRequest(url + '?q=' + encodeURIComponent(evasionResult.modifiedPayload), { method, headers, proxyUrl });
    }
  }

  if (!body && evasionResult.modifiedPayload) {
    body = `q=${encodeURIComponent(evasionResult.modifiedPayload)}`;
  }

  return sendRequest(url, { method, headers, body, proxyUrl });
}

export function isBlocked(response: HttpResponse): boolean {
  return (
    response.status === 403 ||
    response.status === 406 ||
    response.status === 419 ||
    response.body.toLowerCase().includes('blocked') ||
    response.body.toLowerCase().includes('forbidden') ||
    response.body.toLowerCase().includes('denied') ||
    response.body.toLowerCase().includes('security check')
  );
}

export function isRateLimited(response: HttpResponse): boolean {
  return response.status === 429 || !!response.headers['retry-after'];
}
