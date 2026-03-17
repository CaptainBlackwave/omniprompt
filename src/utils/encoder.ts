export function base64Encode(payload: string): string {
  return Buffer.from(payload).toString('base64');
}

export function urlEncode(payload: string): string {
  return encodeURIComponent(payload);
}

export function doubleUrlEncode(payload: string): string {
  return encodeURIComponent(encodeURIComponent(payload));
}

export function hexEncode(payload: string): string {
  return payload.split('').map(c => c.charCodeAt(0).toString(16).padStart(2, '0')).join('');
}

export function unicodeEncode(payload: string): string {
  return payload.split('').map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('');
}

export function tabObfuscate(payload: string): string {
  return payload.replace(/ /g, '\t');
}

export function randomizeCase(payload: string): string {
  return payload.split('').map(c => 
    Math.random() > 0.5 ? c.toUpperCase() : c.toLowerCase()
  ).join('');
}

export function injectComments(payload: string): string {
  const parts = payload.split(/([\s\(\)])/);
  return parts.map((part, i) => {
    if (part.length > 1 && /[a-zA-Z]/.test(part)) {
      return part.slice(0, 1) + '/*comment*/' + part.slice(1);
    }
    return part;
  }).join('');
}

export function nullByteInject(payload: string): string {
  return '\x00' + payload;
}

export function htmlEntityEncode(payload: string): string {
  return payload.split('').map(c => 
    '&#' + c.charCodeAt(0) + ';'
  ).join('');
}

export function mixedEncoding(payload: string): string {
  return btoa(urlEncode(payload));
}

export const tamperFunctions: Record<string, (payload: string) => string> = {
  base64: base64Encode,
  url: urlEncode,
  double_url: doubleUrlEncode,
  hex: hexEncode,
  unicode: unicodeEncode,
  tab: tabObfuscate,
  case: randomizeCase,
  comment: injectComments,
  nullbyte: nullByteInject,
  html: htmlEntityEncode,
  mixed: mixedEncoding,
};
