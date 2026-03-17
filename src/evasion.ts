import type { HttpResponse } from '../utils/http';

export interface EvasionTechnique {
  name: string;
  category: string;
  description: string;
  apply: (payload: string, options?: EvasionOptions) => EvasionResult;
}

export interface EvasionOptions {
  paddingSize?: number;
  proxyUrl?: string;
  headers?: Record<string, string>;
}

export interface EvasionResult {
  modifiedPayload?: string;
  modifiedHeaders?: Record<string, string>;
  modifiedBody?: string;
  contentType?: string;
  method?: string;
}

export interface RateLimitConfig {
  maxRequests: number;
  windowMs: number;
  backoffMs: number;
  jitterMs: number;
}

const commonEnglishWords = [
  'the', 'be', 'to', 'of', 'and', 'a', 'in', 'that', 'have', 'I',
  'it', 'for', 'not', 'on', 'with', 'he', 'as', 'you', 'do', 'at',
  'this', 'but', 'his', 'by', 'from', 'they', 'we', 'say', 'her', 'she',
  'or', 'an', 'will', 'my', 'one', 'all', 'would', 'there', 'their', 'what',
];

const benignHtmlTags = [
  '<div>', '<span>', '<p>', '<br>', '<hr>', '<img>', '<a>', '<ul>', '<ol>', '<li>',
  '<table>', '<tr>', '<td>', '<th>', '<form>', '<input>', '<button>', '<label>', '<select>',
];

function generateJunkPadding(size: number): string {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ';
  let result = '';
  for (let i = 0; i < size; i++) {
    result += chars[Math.floor(Math.random() * chars.length)];
  }
  return result;
}

function injectBenignTokens(payload: string): string {
  const word = commonEnglishWords[Math.floor(Math.random() * commonEnglishWords.length)];
  const tag = benignHtmlTags[Math.floor(Math.random() * benignHtmlTags.length)];
  return `${word} ${payload} ${word} ${tag}`;
}

export const evasionTechniques: Record<string, EvasionTechnique> = {
  hpp: {
    name: 'HTTP_Parameter_Pollution',
    category: 'Protocol',
    description: 'Split payload across multiple identical parameters',
    apply: (payload: string) => {
      const parts = payload.split(' ');
      const params: string[] = [];
      for (let i = 0; i < Math.min(parts.length, 3); i++) {
        params.push(parts[i] || '');
      }
      return {
        modifiedPayload: params.join('&q='),
      };
    },
  },

  hppConcatenation: {
    name: 'HPP_Concatenation',
    category: 'Protocol',
    description: 'Payload split across params that backend concatenates',
    apply: (payload: string) => {
      const mid = Math.floor(payload.length / 2);
      return {
        modifiedPayload: `q=${encodeURIComponent(payload.slice(0, mid))}&q=${encodeURIComponent(payload.slice(mid))}`,
      };
    },
  },

  chunkedEncoding: {
    name: 'Chunked_Transfer_Encoding',
    category: 'Protocol',
    description: 'Fragment request body into chunks',
    apply: (payload: string) => {
      const chunkSize = 4;
      const chunks: string[] = [];
      for (let i = 0; i < payload.length; i += chunkSize) {
        chunks.push(payload.slice(i, i + chunkSize));
      }
      return {
        modifiedBody: chunks.join('\r\n') + '\r\n',
      };
    },
  },

  headerSpoofing: {
    name: 'Header_Spoofing',
    category: 'Protocol',
    description: 'Spoof headers to bypass IP-based filtering',
    apply: (payload: string, options?: EvasionOptions) => {
      const headers: Record<string, string> = {
        'X-Forwarded-For': '127.0.0.1',
        'X-Remote-IP': '127.0.0.1',
        'X-Originating-IP': '127.0.0.1',
        'X-Real-IP': '127.0.0.1',
        'X-Forwarded-Host': 'localhost',
        'X-Host': 'localhost',
        ...options?.headers,
      };
      return { modifiedPayload: payload, modifiedHeaders: headers };
    },
  },

  headerSpoofingRandom: {
    name: 'Header_Spoofing_Random',
    category: 'Protocol',
    description: 'Randomize spoofed header values',
    apply: (payload: string) => {
      const ips = ['127.0.0.1', '10.0.0.1', '192.168.1.1', 'localhost', '0.0.0.0'];
      const headers: Record<string, string> = {
        'X-Forwarded-For': ips[Math.floor(Math.random() * ips.length)],
        'X-Remote-IP': ips[Math.floor(Math.random() * ips.length)],
        'X-Originating-IP': ips[Math.floor(Math.random() * ips.length)],
        'X-Client-IP': ips[Math.floor(Math.random() * ips.length)],
      };
      return { modifiedPayload: payload, modifiedHeaders: headers };
    },
  },

  jsonNested: {
    name: 'JSON_Nested',
    category: 'Parsing',
    description: 'Nest payload in deep JSON structure',
    apply: (payload: string) => {
      const jsonPayload = {
        data: {
          request: {
            params: {
              q: payload,
              extra: { nested: true },
            },
          },
        },
      };
      return {
        modifiedBody: JSON.stringify(jsonPayload),
        contentType: 'application/json',
      };
    },
  },

  jsonMismatched: {
    name: 'Content_Type_Mismatch',
    category: 'Parsing',
    description: 'Send JSON body with URL-encoded content-type',
    apply: (payload: string) => {
      const jsonPayload = JSON.stringify({ q: payload });
      return {
        modifiedBody: `q=${encodeURIComponent(jsonPayload)}`,
        contentType: 'application/x-www-form-urlencoded',
      };
    },
  },

  jsonArray: {
    name: 'JSON_Array_Payload',
    category: 'Parsing',
    description: 'Send payload in JSON array',
    apply: (payload: string) => {
      const jsonPayload = [
        { type: 'query', value: payload },
        { type: 'normal', value: 'test' },
      ];
      return {
        modifiedBody: JSON.stringify(jsonPayload),
        contentType: 'application/json',
      };
    },
  },

  paddingMode: {
    name: 'Padding_Mode',
    category: 'Size',
    description: 'Inject garbage data to push payload out of WAF inspection window',
    apply: (payload: string, options?: EvasionOptions) => {
      const paddingSize = options?.paddingSize || 10240;
      const garbage = generateJunkPadding(paddingSize);
      return {
        modifiedPayload: `${garbage}${payload}`,
      };
    },
  },

  paddingPrepend: {
    name: 'Garbage_Padding_Prepend',
    category: 'Size',
    description: 'Prepend large padding before actual payload',
    apply: (payload: string, options?: EvasionOptions) => {
      const paddingSize = options?.paddingSize || 8192;
      const garbage = generateJunkPadding(paddingSize);
      return {
        modifiedBody: `garbage=${encodeURIComponent(garbage)}&q=${encodeURIComponent(payload)}`,
      };
    },
  },

  paddingPostpend: {
    name: 'Garbage_Padding_Postpend',
    category: 'Size',
    description: 'Postpend large padding after payload',
    apply: (payload: string, options?: EvasionOptions) => {
      const paddingSize = options?.paddingSize || 8192;
      const garbage = generateJunkPadding(paddingSize);
      return {
        modifiedBody: `q=${encodeURIComponent(payload)}&garbage=${encodeURIComponent(garbage)}`,
      };
    },
  },

  mlJunkPadding: {
    name: 'ML_Junk_Padding',
    category: 'ML',
    description: 'Inject benign tokens to lower maliciousness score',
    apply: (payload: string) => {
      const padded = injectBenignTokens(payload);
      return { modifiedPayload: padded };
    },
  },

  mlMultipleTokens: {
    name: 'ML_Multiple_Benign_Tokens',
    category: 'ML',
    description: 'Inject multiple benign tokens around payload',
    apply: (payload: string) => {
      const words = Array(5).fill(0).map(() => commonEnglishWords[Math.floor(Math.random() * commonEnglishWords.length)]);
      const tags = Array(3).fill(0).map(() => benignHtmlTags[Math.floor(Math.random() * benignHtmlTags.length)]);
      const padded = `${words.join(' ')} ${payload} ${words.reverse().join(' ')} ${tags.join('')}`;
      return { modifiedPayload: padded };
    },
  },

  mlMixedPadding: {
    name: 'ML_Mixed_Padding',
    category: 'ML',
    description: 'Mix benign tokens with benign JSON data',
    apply: (payload: string) => {
      const junk = generateJunkPadding(500);
      const benignJson = JSON.stringify({
        search: payload,
        user_query: junk.slice(0, 100),
        metadata: { timestamp: Date.now(), session: 'normal' },
      });
      return { modifiedBody: benignJson, contentType: 'application/json' };
    },
  },

  nullBytePrepend: {
    name: 'Null_Byte_Prepend',
    category: 'Encoding',
    description: 'Prepend null bytes to payload',
    apply: (payload: string) => {
      const nullBytes = '\x00\x00\x00';
      return { modifiedPayload: nullBytes + payload };
    },
  },

  nullByteScatter: {
    name: 'Null_Byte_Scatter',
    category: 'Encoding',
    description: 'Scatter null bytes throughout payload',
    apply: (payload: string) => {
      let result = '';
      for (const char of payload) {
        result += char + '\x00';
      }
      return { modifiedPayload: result };
    },
  },

  methodOverride: {
    name: 'Method_Override',
    category: 'Protocol',
    description: 'Override HTTP method via header',
    apply: (payload: string) => {
      return {
        modifiedPayload: payload,
        modifiedHeaders: { 'X-HTTP-Method-Override': 'POST' },
        method: 'GET',
      };
    },
  },

  formMethodPost: {
    name: 'Form_Method_In_Body',
    category: 'Protocol',
    description: 'Send GET params in POST body',
    apply: (payload: string) => {
      return {
        modifiedBody: `q=${encodeURIComponent(payload)}`,
        method: 'POST',
        contentType: 'application/x-www-form-urlencoded',
      };
    },
  },

  duplicateHeaders: {
    name: 'Duplicate_Headers',
    category: 'Protocol',
    description: 'Send duplicate headers with different values',
    apply: (payload: string) => {
      return {
        modifiedPayload: payload,
        modifiedHeaders: {
          'Accept': 'text/html',
          'Accept-Language': 'en-US',
        },
      };
    },
  },

  partialUrlEncoding: {
    name: 'Partial_Url_Encoding',
    category: 'Encoding',
    description: 'Partially encode URL-special characters',
    apply: (payload: string) => {
      const charsToEncode = ['=', '&', '<', '>', '"', "'"];
      let result = payload;
      for (const char of charsToEncode) {
        if (result.includes(char) && Math.random() > 0.5) {
          result = result.replace(char, encodeURIComponent(char));
        }
      }
      return { modifiedPayload: result };
    },
  },
};

export function getTechnique(name: string): EvasionTechnique | undefined {
  return evasionTechniques[name];
}

export function getAllTechniques(): EvasionTechnique[] {
  return Object.values(evasionTechniques);
}

export function getTechniquesByCategory(category: string): EvasionTechnique[] {
  return Object.values(evasionTechniques).filter(t => t.category === category);
}

export const techniqueCategories = [
  'Protocol',
  'Parsing',
  'Size',
  'ML',
  'Encoding',
];
