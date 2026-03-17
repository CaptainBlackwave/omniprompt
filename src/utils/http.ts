export interface HttpResponse {
  status: number;
  headers: Record<string, string>;
  body: string;
  cookies: Record<string, string>;
}

export async function sendRequest(
  url: string,
  method: string = 'GET',
  headers: Record<string, string> = {},
  body?: string
): Promise<HttpResponse> {
  const response = await fetch(url, {
    method,
    headers: {
      'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
      ...headers,
    },
    body,
    redirect: 'follow',
  });

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
